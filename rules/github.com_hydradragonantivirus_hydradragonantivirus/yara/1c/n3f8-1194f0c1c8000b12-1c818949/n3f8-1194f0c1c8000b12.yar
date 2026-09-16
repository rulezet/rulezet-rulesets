rule n3f8_1194f0c1c8000b12 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=n3f8.1194f0c1c8000b12"
    cluster         = "n3f8.1194f0c1c8000b12"
    cluster_size    = "4"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180911"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "bankbot banker androidos"
    md5_hashes      = "['358213b84986bf156d7ede09b0c350fef07a95a4','eacfd3eac77791c3c45b4edae8fc6acea9d75477','889f76ae3a0ce461bdf39e5f88e4f66ba866c894']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=n3f8.1194f0c1c8000b12"

  strings:
    $hex_string = { 79 73 74 65 6d 3b 00 15 4c 6a 61 76 61 2f 6c 61 6e 67 2f 54 68 72 6f 77 61 62 6c 65 3b 00 29 4c 6a 61 76 61 2f 6c 61 6e 67 2f 55 6e 73 75 70 70 6f 72 74 65 64 4f 70 65 72 61 74 69 6f 6e 45 78 }

  condition:
    filesize > 262144 and filesize < 1048576
    and $hex_string
}