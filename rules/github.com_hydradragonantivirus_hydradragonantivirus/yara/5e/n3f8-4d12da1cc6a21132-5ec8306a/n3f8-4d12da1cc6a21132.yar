rule n3f8_4d12da1cc6a21132 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=n3f8.4d12da1cc6a21132"
    cluster         = "n3f8.4d12da1cc6a21132"
    cluster_size    = "3"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180911"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "androidos cloud dldr"
    md5_hashes      = "['01fec3f6d22e701d9a2d996eaec3ca9d735197a4','4510d11e149cb3e5c3efa83665f809629c179e65','7c4f0ce91808d32cb6acfc349875f095f4c7e745']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=n3f8.4d12da1cc6a21132"

  strings:
    $hex_string = { 64 79 2f 50 69 6e 67 3b 00 32 4c 63 6f 6d 2f 73 71 75 61 72 65 75 70 2f 6f 6b 68 74 74 70 2f 69 6e 74 65 72 6e 61 6c 2f 73 70 64 79 2f 50 75 73 68 4f 62 73 65 72 76 65 72 24 31 3b 00 30 4c 63 }

  condition:
    filesize > 262144 and filesize < 1048576
    and $hex_string
}