rule o2706_6914b9e1ca000b32 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=o2706.6914b9e1ca000b32"
    cluster         = "o2706.6914b9e1ca000b32"
    cluster_size    = "46"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180909"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "browsefox yontoo malicious"
    md5_hashes      = "['fc40c5f4abdd5a0ae7e58779bd012351638c20ed','3f1a41c0f00e056e8748c4443f010fa0119715ff','aff146b47ad1c6f67f368591f73f8954f54f53a8']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=o2706.6914b9e1ca000b32"

  strings:
    $hex_string = { 31 64 34 65 34 33 37 38 39 62 32 39 33 35 39 32 39 33 61 30 66 36 34 34 61 66 63 00 6d 5f 50 6c 75 67 69 6e 54 68 72 65 61 64 00 6d 5f 56 65 72 73 69 6f 6e 00 49 6e 69 74 69 61 6c 69 7a 65 4c }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}