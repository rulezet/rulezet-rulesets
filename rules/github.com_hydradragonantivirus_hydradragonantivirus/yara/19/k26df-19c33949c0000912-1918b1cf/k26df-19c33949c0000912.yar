rule k26df_19c33949c0000912 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=k26df.19c33949c0000912"
    cluster         = "k26df.19c33949c0000912"
    cluster_size    = "451"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "linkury webtoolbar pirax"
    md5_hashes      = "['0df1a87f303249f6c5d29d015dbff2006bda7b7f','20067d6a42eedbdb6c31c49a08308637a2dd815b','ccf22279874d6dc6820cb034b360db69d34337c3']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=k26df.19c33949c0000912"

  strings:
    $hex_string = { 77 e8 f7 40 57 65 67 98 f7 5f 57 e1 67 66 e7 1f 57 65 67 96 e7 cf 57 61 77 45 e7 4e 57 b5 77 e4 67 55 77 b5 77 38 07 db 67 b5 77 29 27 dd 57 e0 67 c5 e7 3b 57 e2 77 b4 e7 eb 57 ea 77 0d 17 8b }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}