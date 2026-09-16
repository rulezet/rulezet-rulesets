rule k26bb_293b19609cd96996 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=k26bb.293b19609cd96996"
    cluster         = "k26bb.293b19609cd96996"
    cluster_size    = "233"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "installcore dealply malicious"
    md5_hashes      = "['4170569a6d0390a7cc797629482711be93def991','fc3cb28d6f5ab34581a9e7e10dd526ad95d13365','4ee7206b88a4ff4a1895fd9c42c53424a8f89991']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=k26bb.293b19609cd96996"

  strings:
    $hex_string = { 15 93 16 01 f0 39 c8 51 00 2b 8c d3 d8 9f 8e 67 88 68 c4 ff cb 5c a3 59 3d ba 4c a6 88 29 3e e5 28 04 20 cc e4 52 fc 7e 3b 56 a7 66 e2 9a 7b f4 dd d5 c5 91 26 46 95 10 c9 81 86 a9 72 78 31 96 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}