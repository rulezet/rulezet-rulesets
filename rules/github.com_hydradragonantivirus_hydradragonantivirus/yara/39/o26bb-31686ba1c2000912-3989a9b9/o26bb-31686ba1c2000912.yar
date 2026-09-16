rule o26bb_31686ba1c2000912 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=o26bb.31686ba1c2000912"
    cluster         = "o26bb.31686ba1c2000912"
    cluster_size    = "682"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "downloadsponsor malicious unwanted"
    md5_hashes      = "['f7470752b925f30db61af11f7bcbd5e9762d1443','a6e1053da3676e408fe1a8fefc7098c44a806958','32b13b3767196be1f55116067709c581170cead5']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=o26bb.31686ba1c2000912"

  strings:
    $hex_string = { 26 1b 2d b3 d2 94 9d 01 20 12 a9 87 1a 82 4d 2f 3d a1 67 ef dc b0 22 b8 39 14 a6 fc c9 1f b4 7a 62 5f 8e d1 47 0c 44 58 2e 1c 61 cd 03 bf 16 59 4c 63 cf 8d b7 31 96 73 08 4b c2 17 77 0e a7 ed }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}