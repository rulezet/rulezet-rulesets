rule o3e9_2b102a08d9e28912 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=o3e9.2b102a08d9e28912"
    cluster      = "o3e9.2b102a08d9e28912"
    cluster_size = "2812"
    filetype     = ""
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171109"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "strictor noobyprotect advml"
    md5_hashes   = "['00375d76cadf50f91444c2107012ea5b','0059bff0b52ffac7bb94ad103ad97bf4','017714606f28cee8db3936d7b59d3399']"

  strings:
    $hex_string = { 87 d5 db 4d 48 7a 29 e6 db b0 27 92 0d 6e d1 ab 32 35 11 f3 c0 2d 19 8a 81 76 6e b6 fc 44 97 02 10 df c4 9b 3b 7a 64 00 20 6f 98 86 62 39 c9 1c 01 60 85 d0 7c dc b3 b1 d5 e4 98 59 66 e4 ce 5e }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}