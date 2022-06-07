
#include <span>
#include <string>
#include <cinttypes>
#include <cstdio>
#include "fast_io/fast_io.h"
#include "fast_io/fast_io_device.h"

struct
#if __has_cpp_attribute(__gnu__::__may_alias__)
[[__gnu__::__may_alias__]]
#endif
pcap_hdr {
    uint_least32_t magic_number;   /* magic number */
    uint_least16_t version_major;  /* major version number */
    uint_least16_t version_minor;  /* minor version number */
    uint_least32_t thiszone;       /* GMT to local correction */
    uint_least32_t sigfigs;        /* accuracy of timestamps */
    uint_least32_t snaplen;        /* max length of captured packets, in octets */
    uint_least32_t network;        /* data link type */
};

/* Packet header */
struct
#if __has_cpp_attribute(__gnu__::__may_alias__)
[[__gnu__::__may_alias__]]
#endif
pcaprec_hdr {
    uint_least32_t ts_sec;         /* timestamp seconds */
    uint_least32_t ts_usec;        /* timestamp microseconds */
    uint_least32_t incl_len;       /* number of octets of packet saved in file */
    uint_least32_t orig_len;       /* actual length of packet */
};

int main(int argc, char **argv)  try {
    using namespace fast_io::mnp;
    if (argc != 3) {
        return 2;
    }
    fast_io::native_file_loader pcap(os_c_str(argv[1]), fast_io::open_mode::follow | fast_io::open_mode::in);
    fast_io::obuf_file out(os_c_str(argv[2]));
    pcap_hdr *hdr(reinterpret_cast<pcap_hdr *>(pcap.data()));
    println("magic:", addrvw(hdr->magic_number));
    pcap_hdr hdr2 = *hdr;
    hdr2.magic_number = 0xa1b23c4d;
    std::byte *hdr2_ref(reinterpret_cast<std::byte *>(&hdr2));
    write(out, hdr2_ref, hdr2_ref + sizeof(hdr2));
    std::size_t ptr(sizeof(hdr2));
    std::string line;
    std::size_t n_pkt(0);
    while (ptr < pcap.size()) {
        pcaprec_hdr *rec(reinterpret_cast<pcaprec_hdr *>(pcap.data() + ptr));
        ptr += sizeof(pcaprec_hdr);
        pcaprec_hdr rec2(*rec);
        rec2.ts_usec = rec2.ts_usec * 1000;
        std::byte *rec2_ref(reinterpret_cast<std::byte *>(&rec2));
        write(out, rec2_ref, rec2_ref + sizeof(rec2));
        std::size_t pktlen(rec2.incl_len);
        write(out, pcap.data() + ptr, pcap.data() + ptr + pktlen);
        ptr += pktlen;
        n_pkt++;
    }
    println("n_pkt:",n_pkt);
    return 0;
}catch(fast_io::error e) {
    perrln(e);
}

