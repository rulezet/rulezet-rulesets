rule k2321_096d5923d9eb1912 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k2321.096d5923d9eb1912"
    cluster      = "k2321.096d5923d9eb1912"
    cluster_size = "6"
    filetype     = "application/gzip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "vobfus razy autorun"
    md5_hashes   = "['8c6e82225796ec54eeaa7361e219f6b3','8ea062fa38fecae47021f60eb53d1508','e301091467e51830aa0099a6a038bf7b']"

  strings:
    $hex_string = { 98 39 27 d2 83 3d fb 82 dd 89 d9 e7 03 73 b3 0d cd 8c d0 42 58 78 86 18 87 66 79 ff 38 dc 42 6b 19 47 d5 96 b7 1a a1 71 a3 61 0a 35 5b 70 c4 de 32 2e 16 1f a4 66 4b a9 2b 5f 4a f1 02 09 bc 12 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}