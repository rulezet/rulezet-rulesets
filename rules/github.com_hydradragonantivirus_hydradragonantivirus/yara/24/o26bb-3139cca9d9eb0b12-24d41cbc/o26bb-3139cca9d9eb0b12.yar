rule o26bb_3139cca9d9eb0b12 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=o26bb.3139cca9d9eb0b12"
    cluster         = "o26bb.3139cca9d9eb0b12"
    cluster_size    = "9"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "razy adload malicious"
    md5_hashes      = "['ccf2e3cd4bc2d71e8cee5fd166643257abf4642f','ed07a79f1a3e9d6e4d87901c6b6f68c6be2fc182','d0c81d0f0a98248c7023c425270ccc9e01a9dfe2']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=o26bb.3139cca9d9eb0b12"

  strings:
    $hex_string = { 6f 79 45 6e 76 69 72 6f 6e 6d 65 6e 74 42 6c 6f 63 6b 00 55 53 45 52 45 4e 56 2e 64 6c 6c 00 3f 00 47 65 74 41 64 61 70 74 65 72 73 49 6e 66 6f 00 49 50 48 4c 50 41 50 49 2e 44 4c 4c 00 00 05 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}