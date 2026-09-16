rule o26d7_09105998dabb0912 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=o26d7.09105998dabb0912"
    cluster         = "o26d7.09105998dabb0912"
    cluster_size    = "108"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180909"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "razy amonetize kryptik"
    md5_hashes      = "['3717fb13a9288a9e8f773a373babd056672952b9','2eaddb191e6776a8557b6cdbcf0447d4002ab6b9','c9e2e392b558154228f2c5b4b4e4c90ef316b0f8']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=o26d7.09105998dabb0912"

  strings:
    $hex_string = { 3e c0 fb 49 6c 80 85 59 89 12 3d 46 b5 7f 74 5e d5 d7 d6 d3 4d ca 53 8d ea 56 8d 73 10 35 5c 49 ee 04 0b 7e 72 31 8d 43 80 57 8d f3 82 0d 48 04 66 87 97 42 00 00 8d 82 1f 8b 40 02 88 c0 fb 44 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}