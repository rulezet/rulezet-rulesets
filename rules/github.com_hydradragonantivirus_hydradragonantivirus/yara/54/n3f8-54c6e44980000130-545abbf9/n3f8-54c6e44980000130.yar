rule n3f8_54c6e44980000130 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=n3f8.54c6e44980000130"
    cluster         = "n3f8.54c6e44980000130"
    cluster_size    = "15"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "androidos banker piom"
    md5_hashes      = "['a9aed11b7a071fe10784c3cd891abc6ba814b7b2','5eaf86d181f2e04f06f184990b65158bf38ee360','1c75c375d9f50eb75aa30ed3601ce704ac1ea93c']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=n3f8.54c6e44980000130"

  strings:
    $hex_string = { 6c 65 61 6e 65 72 3b 00 19 4c 73 75 6e 2f 6e 69 6f 2f 63 68 2f 44 69 72 65 63 74 42 75 66 66 65 72 3b 00 04 4d 41 49 4e 00 0c 4d 41 4e 55 46 41 43 54 55 52 45 52 00 0d 4d 41 50 50 45 52 5f 43 }

  condition:
    filesize > 262144 and filesize < 1048576
    and $hex_string
}