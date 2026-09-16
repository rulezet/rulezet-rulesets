rule o26bb_0b4935b969496292 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=o26bb.0b4935b969496292"
    cluster         = "o26bb.0b4935b969496292"
    cluster_size    = "57"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "mdeclass btcmine score"
    md5_hashes      = "['ebdc0c772ee217a91b87635beef98a5b9a36cca6','fd105087249a8c4e21a02afa104ca20f79ca254a','bec538e4f75c4e082ca13858bf4ef6d3d0861a78']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=o26bb.0b4935b969496292"

  strings:
    $hex_string = { bf 14 fe 9f a0 78 fd f7 3b 3c 88 4c 80 67 9e 3a d9 81 da 36 ad 04 f5 84 46 b0 87 bb 5b 4e c0 61 ae 8f 05 f1 1f 40 f2 00 90 1c 49 f0 43 23 82 a8 93 27 ee 0e 08 6b 55 41 59 16 e3 a6 b6 4d 2b 83 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}