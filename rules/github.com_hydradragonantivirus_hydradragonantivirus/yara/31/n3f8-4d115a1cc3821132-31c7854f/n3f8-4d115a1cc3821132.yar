rule n3f8_4d115a1cc3821132 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=n3f8.4d115a1cc3821132"
    cluster         = "n3f8.4d115a1cc3821132"
    cluster_size    = "9"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180911"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "androidos dldr ehco"
    md5_hashes      = "['20def3c99788c0fe609271006a8a5d08e8a97793','7f75109bd3c3add1b57d3a6bc588b6d0b857b3a8','9f2500fc6e24fb1676100dbeeda47c0e700069ca']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=n3f8.4d115a1cc3821132"

  strings:
    $hex_string = { 4d 65 74 68 6f 64 3c 54 54 3b 3e 3b 00 2f 4c 63 6f 6d 2f 73 71 75 61 72 65 75 70 2f 6f 6b 68 74 74 70 2f 69 6e 74 65 72 6e 61 6c 2f 50 6c 61 74 66 6f 72 6d 24 41 6e 64 72 6f 69 64 3b 00 40 4c }

  condition:
    filesize > 262144 and filesize < 1048576
    and $hex_string
}