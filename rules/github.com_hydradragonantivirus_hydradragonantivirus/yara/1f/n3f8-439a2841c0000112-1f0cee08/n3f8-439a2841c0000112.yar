rule n3f8_439a2841c0000112 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=n3f8.439a2841c0000112"
    cluster         = "n3f8.439a2841c0000112"
    cluster_size    = "145"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "zdtad androidos inoco"
    md5_hashes      = "['43078f4c0e34f591ff4919391c2a5d22bb9825d5','3d647026df11224dfe94c5f748b8095a96bac8f2','8aef943d01bb90ceee94e9ddab7f53ef8bc98756']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=n3f8.439a2841c0000112"

  strings:
    $hex_string = { 9c 89 e4 b8 8b e8 bd bd e4 bb bb e5 8a a1 e5 85 b3 e9 97 ad e6 97 b6 e9 92 9f 29 00 01 45 00 03 45 4e 44 00 2b 45 72 72 6f 72 20 2d 2d 3e 20 42 61 73 65 41 63 74 69 76 69 74 79 2e 69 6e 66 6c }

  condition:
    filesize > 262144 and filesize < 1048576
    and $hex_string
}