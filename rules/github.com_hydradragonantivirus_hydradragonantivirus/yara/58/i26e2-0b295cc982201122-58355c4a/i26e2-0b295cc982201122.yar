rule i26e2_0b295cc982201122 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=i26e2.0b295cc982201122"
    cluster         = "i26e2.0b295cc982201122"
    cluster_size    = "13"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "dorkbot winlnk darkbot"
    md5_hashes      = "['b6ead5d94742c26d1e38608a25719a0c1f1a9e40','fdb538330e6e73428a2a9cbbd42afefb36378125','909f585c1373b698e3821d3db0e4fcb04f6df3a9']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=i26e2.0b295cc982201122"

  strings:
    $hex_string = { 00 25 00 53 00 79 00 73 00 74 00 65 00 6d 00 52 00 6f 00 6f 00 74 00 25 00 5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 00 00 00 00 00 }

  condition:
    filesize > 1024 and filesize < 4096
    and $hex_string
}