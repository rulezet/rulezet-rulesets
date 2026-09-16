rule i26e2_2b0558a0ea010b30 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=i26e2.2b0558a0ea010b30"
    cluster         = "i26e2.2b0558a0ea010b30"
    cluster_size    = "3"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "boxter powershell fbqh"
    md5_hashes      = "['db0f2fa56c660ba476954c0ad037430ac536404a','821d7bdd61028738abc1ccd6db81d57aaa2e8b95','f23e15d576e86f03155db717b3af335e01ff8a0c']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=i26e2.2b0558a0ea010b30"

  strings:
    $hex_string = { 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 50 00 6f 00 77 00 65 00 72 00 53 00 68 00 65 00 6c 00 6c 00 5c 00 76 00 31 00 2e 00 30 00 5c 00 70 }

  condition:
    filesize > 1024 and filesize < 4096
    and $hex_string
}