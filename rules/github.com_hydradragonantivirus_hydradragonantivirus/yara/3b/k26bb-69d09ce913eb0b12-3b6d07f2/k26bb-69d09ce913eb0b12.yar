rule k26bb_69d09ce913eb0b12 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=k26bb.69d09ce913eb0b12"
    cluster         = "k26bb.69d09ce913eb0b12"
    cluster_size    = "16"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "mywebsearch mindspark malicious"
    md5_hashes      = "['794c757c3f6c851e479d6e8aff2744b17a72d622','cd35e5ce159c77a6e009e2878b463729c875e86f','8ea2d42bbb37aefa4e628886780b194334c98e49']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=k26bb.69d09ce913eb0b12"

  strings:
    $hex_string = { d0 80 e2 01 f6 da 1b d2 81 e2 20 83 b8 ed d1 e8 33 c2 4e 75 ea 89 04 8d 98 18 43 00 41 81 f9 00 01 00 00 7c d5 8b 54 24 10 8b 44 24 08 85 d2 f7 d0 76 23 8b 4c 24 0c 57 0f b6 39 8b f0 81 e6 ff }

  condition:
    filesize > 262144 and filesize < 1048576
    and $hex_string
}