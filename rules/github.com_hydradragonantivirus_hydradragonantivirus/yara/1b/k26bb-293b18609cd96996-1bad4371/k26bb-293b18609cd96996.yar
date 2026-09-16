rule k26bb_293b18609cd96996 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=k26bb.293b18609cd96996"
    cluster         = "k26bb.293b18609cd96996"
    cluster_size    = "213"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "installcore malicious unwanted"
    md5_hashes      = "['5fdb53004f209d8bb2feb5da0c5ee904c5615e50','0060e933fc078dda3014c53ca1b91f3ca422fe5f','342d82d148cc02035005f30f3c903f4e80e4b719']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=k26bb.293b18609cd96996"

  strings:
    $hex_string = { d0 c5 16 e0 93 ad 4f 43 00 44 b4 8f 92 34 fa 56 8a 9c d9 03 b1 05 60 42 d5 f7 b7 21 64 14 53 31 fc 9f 49 48 8d 6b a1 ca e1 81 39 ce 5f 33 2c f6 58 61 d3 db 98 17 3d 6c 7f 09 de e6 0b 3b f8 fe }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}