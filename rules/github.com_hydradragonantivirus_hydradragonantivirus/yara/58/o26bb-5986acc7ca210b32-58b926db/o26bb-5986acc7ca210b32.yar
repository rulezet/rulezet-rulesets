rule o26bb_5986acc7ca210b32 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=o26bb.5986acc7ca210b32"
    cluster         = "o26bb.5986acc7ca210b32"
    cluster_size    = "3"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180909"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "dealply malicious dmfpl"
    md5_hashes      = "['3cd49e289d9465ce8a453d4ccac06cc44896c356','0849d85bfa976a171a2e347e652327a5cfcdae9f','db654c048b62dbb685e31cbdbc3da7a5af6e5cbd']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=o26bb.5986acc7ca210b32"

  strings:
    $hex_string = { 8b 08 42 02 54 11 9b 08 45 11 40 04 39 04 ab 06 5f 11 73 0f 13 0e 98 0f d1 08 d8 08 c2 0c dd 09 ff 03 22 06 4d 05 df 10 b2 04 ff 0f c4 09 97 0a 74 0b 74 0b e8 08 f8 08 38 09 49 09 4b 09 44 09 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}