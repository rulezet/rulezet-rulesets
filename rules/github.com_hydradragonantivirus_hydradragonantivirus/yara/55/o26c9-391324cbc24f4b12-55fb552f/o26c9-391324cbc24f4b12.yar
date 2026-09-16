rule o26c9_391324cbc24f4b12 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=o26c9.391324cbc24f4b12"
    cluster         = "o26c9.391324cbc24f4b12"
    cluster_size    = "230"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180909"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "bsymem dnscleaner tsklnk"
    md5_hashes      = "['bd295221b6d38168e5856e5c00ab56feadff549f','b10c90c93fe5b5fdc469163e07e0a54dcaf6abb3','d297312eef83bad0f7e196bb5a8dcfb0a7a34c3c']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=o26c9.391324cbc24f4b12"

  strings:
    $hex_string = { c5 48 8d 4d e0 41 8b d5 ff 15 de fc 18 00 44 39 65 70 74 05 45 8b cd eb 35 8b 4b 24 83 f9 ff 75 0c 41 f7 de 45 1b c9 41 83 e1 03 eb 21 b2 c0 3a ca 76 18 0f b7 c1 66 c1 e8 08 3a c2 76 0d c1 e9 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}