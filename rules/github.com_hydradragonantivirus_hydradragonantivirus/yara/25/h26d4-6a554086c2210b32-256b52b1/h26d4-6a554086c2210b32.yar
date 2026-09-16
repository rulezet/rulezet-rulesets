rule h26d4_6a554086c2210b32 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=h26d4.6a554086c2210b32"
    cluster         = "h26d4.6a554086c2210b32"
    cluster_size    = "116"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "fraudtool heuristic malicious"
    md5_hashes      = "['f6010c92b85947198a5fbc2baea97c7344392f50','976d69a8b43986e0c9a6e271071374787e5d2c66','d1e4db47e48ab4835ecaa27de12a83e9b3d89354']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=h26d4.6a554086c2210b32"

  strings:
    $hex_string = { b8 01 4c cd 21 54 68 69 73 20 70 72 6f 67 72 61 6d 20 63 61 6e 6e 6f 74 20 62 65 20 72 75 6e 20 69 6e 20 44 4f 53 20 6d 6f 64 65 2e 0d 0d 0a 24 00 00 00 00 00 00 00 66 ba d1 a2 22 db bf f1 22 }

  condition:
    filesize > 1024 and filesize < 4096
    and $hex_string
}