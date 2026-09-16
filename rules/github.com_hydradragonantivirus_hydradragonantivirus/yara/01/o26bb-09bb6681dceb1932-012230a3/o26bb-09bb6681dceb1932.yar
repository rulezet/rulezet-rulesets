rule o26bb_09bb6681dceb1932 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=o26bb.09bb6681dceb1932"
    cluster         = "o26bb.09bb6681dceb1932"
    cluster_size    = "4283"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "razy softcnapp adload"
    md5_hashes      = "['0146c83287cb7199e0fb8988886c3f71d1db2828','d946e2b921b4c05ed044e4a50ca28135c5d45db0','97ded5805024e3dd8f5ebfdd96ce6dec23917f0f']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=o26bb.09bb6681dceb1932"

  strings:
    $hex_string = { 56 e8 b1 75 01 00 8b d0 83 c4 0c 85 d2 74 19 85 f6 74 0f 8b ca 2b cf 8a 07 88 04 39 47 83 ee 01 75 f5 5f 8b c2 5e 5d c3 e8 87 c0 f8 ff cc 6a 14 b8 65 1f 55 00 e8 4a 9a 02 00 33 db 8d 4d ec 53 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}