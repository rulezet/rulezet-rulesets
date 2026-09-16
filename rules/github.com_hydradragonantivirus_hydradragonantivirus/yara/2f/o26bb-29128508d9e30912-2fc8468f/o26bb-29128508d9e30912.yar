rule o26bb_29128508d9e30912 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=o26bb.29128508d9e30912"
    cluster         = "o26bb.29128508d9e30912"
    cluster_size    = "20"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "symmi malicious susp"
    md5_hashes      = "['ef44d5b6a33edddeadaf0323d84119a3279b8d9b','e69ec31753736e3addd1db3ed43590d4cfb144d2','65d73ce535bf71590a4c998807e1046e0c1f3825']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=o26bb.29128508d9e30912"

  strings:
    $hex_string = { 03 09 53 3f ce 0d a1 a3 72 41 06 7e ee 82 0e e6 38 a9 d2 1e ab dd 3e da 3c 24 e1 ad 29 b1 c1 eb b8 e3 d1 69 ef 62 9d 60 a6 35 04 6c c3 86 43 f4 1c 8f 36 2d a0 18 de 6a 85 fb e8 f6 9f 67 68 19 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}