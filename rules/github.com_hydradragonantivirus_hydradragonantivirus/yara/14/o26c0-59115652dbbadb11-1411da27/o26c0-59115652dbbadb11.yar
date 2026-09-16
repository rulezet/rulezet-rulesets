rule o26c0_59115652dbbadb11 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=o26c0.59115652dbbadb11"
    cluster         = "o26c0.59115652dbbadb11"
    cluster_size    = "19"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180909"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "symmi kryptik malicious"
    md5_hashes      = "['c5d5f514e3ab0dfd9dd3a529504019f5748a3644','531efddac54dede74fe0cbc4d5a51796e4b2da82','2eb12124c155c9f51e3bac56302d0263cfc80a3f']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=o26c0.59115652dbbadb11"

  strings:
    $hex_string = { 3b 0f 4d d2 57 96 6d 65 98 9b 6f cf 9d 74 e9 33 17 55 f9 2c c8 3f 0e 09 7e cb 32 23 04 bc cd 92 35 bd 20 ad 76 91 c2 0c 7d 4a d3 39 d6 5f c1 8b e5 56 41 10 14 cc 1b 6a fd e7 89 c9 6c f1 a6 36 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}