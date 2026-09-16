rule i26bb_599901e8e4454b92 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=i26bb.599901e8e4454b92"
    cluster         = "i26bb.599901e8e4454b92"
    cluster_size    = "13"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "mywebsearch malicious mindspark"
    md5_hashes      = "['339509ab0f0f66bfbb3cd0bbba3a39a7fa5d4d90','5b22bb15f1209e972c4ecd67f2f38125cdec5b83','32c5d9687710358fda13f7d3ec8306f2c7dcbd88']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=i26bb.599901e8e4454b92"

  strings:
    $hex_string = { 08 57 8b fa 2b f1 85 ff 74 0e 8a 14 0e 84 d2 74 07 88 11 41 4f 4b 75 ee 5f 5e 85 db 75 06 49 b8 7a 00 07 80 c6 01 00 5b 5d c2 04 00 55 8b ec b8 50 81 00 00 e8 68 02 00 00 53 56 57 ff 15 0c 20 }

  condition:
    filesize > 4096 and filesize < 16384
    and $hex_string
}