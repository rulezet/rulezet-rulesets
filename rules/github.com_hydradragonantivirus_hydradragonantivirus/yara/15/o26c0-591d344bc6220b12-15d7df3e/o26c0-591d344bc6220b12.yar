rule o26c0_591d344bc6220b12 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=o26c0.591d344bc6220b12"
    cluster         = "o26c0.591d344bc6220b12"
    cluster_size    = "240"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180909"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "malicious virut attribute"
    md5_hashes      = "['2b5ec39ec52ac4fb65207a2ef03fc762f71bafe8','9d9338bb8b4832f413bb33100974692fbe06088a','0a2d4ccd78f3c7f9d6c1524573a46f5d0b7cac31']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=o26c0.591d344bc6220b12"

  strings:
    $hex_string = { e8 69 c9 29 df ed aa 27 ff fd c3 83 11 6a 47 bb a8 09 39 9e a1 72 82 d2 d9 de 16 ab f2 c0 ba 7c 10 6f 6d 04 b1 c8 52 06 1a c6 b2 1f a9 68 fc 86 3e c5 37 21 b5 43 c4 41 55 a6 36 7f d4 cf 75 b4 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}