rule o2321_391b2949c0000b12 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=o2321.391b2949c0000b12"
    cluster      = "o2321.391b2949c0000b12"
    cluster_size = "6"
    filetype     = "application/gzip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "gate fileinfector aovhryb"
    md5_hashes   = "['24ca4f5c7ea4059496fa88ee05b6695b','41ae9fd0337c2327de7e75ca5b54b151','f3efad8e666ff6b6b842170c0905b469']"

  strings:
    $hex_string = { b3 44 ad 5f fb 57 6c ca cd df d0 5e 22 88 9a 8a b0 66 a0 16 cc cb 03 91 8d 50 90 e4 f1 35 f2 d7 33 c8 f6 b8 d4 6b 73 e6 81 28 f3 52 84 ff ef f0 04 5d 5a bf 3a 30 14 2f ae e9 fc 19 fa 80 c6 9f }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}