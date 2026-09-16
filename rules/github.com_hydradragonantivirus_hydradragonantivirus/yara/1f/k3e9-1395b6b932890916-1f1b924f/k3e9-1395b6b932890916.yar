rule k3e9_1395b6b932890916 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e9.1395b6b932890916"
    cluster      = "k3e9.1395b6b932890916"
    cluster_size = "1843"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "ipamor backdoor xyzbaukwkdpb"
    md5_hashes   = "['001c8a1e7a609b5ea6b5445b25a6f469','003bf94474b056b76f09eb4261b0ac71','023e72a41af907c5642d71931a5e275a']"

  strings:
    $hex_string = { 10 c1 f8 78 27 50 fe a0 88 c2 12 6d 7c f1 34 60 6a 1b 64 85 ea 3b 55 6c 37 04 11 0e 94 0b 80 9b 68 84 aa 17 30 b9 d8 c3 28 d4 39 f0 9c 5f 9a 15 92 fb 9f 4a c9 7e c6 05 22 1f fa 57 33 41 d6 63 }

  condition:
    filesize > 65536 and filesize < 262144
    and $hex_string
}