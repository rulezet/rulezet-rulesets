rule k26d7_259e4acc9ee30b32 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=k26d7.259e4acc9ee30b32"
    cluster         = "k26d7.259e4acc9ee30b32"
    cluster_size    = "108"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "veil malicious skypespam"
    md5_hashes      = "['839910dfba2bf532c89d1c032bc8503a679267c5','1260daf708d6517bbf3e6c3bdc00501b1be93dd8','57530edd0f212ef7fa1dc9e8375cc6098eaec28c']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=k26d7.259e4acc9ee30b32"

  strings:
    $hex_string = { e7 08 09 c2 89 e8 83 c0 01 89 44 24 10 89 f8 c1 e8 0b 0f af 44 24 08 39 c2 72 9c 8d 5c 1b 01 29 c7 29 c2 21 f1 81 fb ff 00 00 00 76 9a 8b 6c 24 10 e9 45 fd ff ff 90 83 c4 18 31 c0 5b 5e 5f 5d }

  condition:
    filesize > 262144 and filesize < 1048576
    and $hex_string
}