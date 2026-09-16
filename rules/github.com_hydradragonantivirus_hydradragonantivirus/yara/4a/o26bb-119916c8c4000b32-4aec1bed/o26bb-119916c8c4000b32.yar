rule o26bb_119916c8c4000b32 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=o26bb.119916c8c4000b32"
    cluster         = "o26bb.119916c8c4000b32"
    cluster_size    = "29"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "patched malicious heuristic"
    md5_hashes      = "['3c5384d2be96ae4326abf96b12c6ce412ef53e44','82fe2d2f0b9a2fdfe1e6304eb9f8a73f0ebdfade','296420fb624dec802b5a119494bb21f4d50a5c1d']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=o26bb.119916c8c4000b32"

  strings:
    $hex_string = { 48 f4 03 c8 51 89 5d fc 43 50 89 5d f0 e8 1d 2d 02 00 59 59 33 c9 85 c0 0f 95 c1 85 c9 75 05 e8 80 0d 00 00 8a 00 3c 5c 74 10 3c 2f 74 0c 0f b6 46 14 50 8b cf e8 47 65 f9 ff 8b 06 8d 4d ec 51 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}