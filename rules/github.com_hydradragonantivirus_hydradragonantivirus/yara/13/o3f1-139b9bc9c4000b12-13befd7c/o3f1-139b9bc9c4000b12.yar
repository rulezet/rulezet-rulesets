rule o3f1_139b9bc9c4000b12 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=o3f1.139b9bc9c4000b12"
    cluster      = "o3f1.139b9bc9c4000b12"
    cluster_size = "43"
    filetype     = "application/zip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171123"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "androidos hiddad hiddenap"
    md5_hashes   = "['018e5b04904465ddbbccc43633f5f3a0','18588245e8b2c4e7c9311bb2141a4ca9','76ffd6d7c5388246bb9f9ee6119e0268']"

  strings:
    $hex_string = { 4d 74 52 4e 53 00 1f 77 ba e5 fa 78 20 1c a5 fc fd a7 1e 55 f2 f3 58 80 6e fe 71 a3 f8 8f 33 07 0c 36 92 f9 e4 2d 2f 75 2e b7 90 e3 34 09 fb e7 35 b9 69 30 0b f1 56 6f 9a 98 9c 81 82 83 7f 0e }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}