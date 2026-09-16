rule o26bb_2914640080000000 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=o26bb.2914640080000000"
    cluster         = "o26bb.2914640080000000"
    cluster_size    = "59905"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "razy attribute hacktool"
    md5_hashes      = "['bd32640c67264f9aabd5ca9d3fce607c20aeb98c','dd8dd77b8694241189e6724178ec8ae1405cbb42','033247ddae9ff13425d4d3623bf075d3911bba19']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=o26bb.2914640080000000"

  strings:
    $hex_string = { 4e 65 78 74 44 6c 67 54 61 62 49 74 65 6d 00 df 02 53 68 6f 77 57 69 6e 64 6f 77 00 00 32 03 77 73 70 72 69 6e 74 66 41 00 09 00 41 70 70 65 6e 64 4d 65 6e 75 41 00 c4 00 44 72 61 77 46 6f 63 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}