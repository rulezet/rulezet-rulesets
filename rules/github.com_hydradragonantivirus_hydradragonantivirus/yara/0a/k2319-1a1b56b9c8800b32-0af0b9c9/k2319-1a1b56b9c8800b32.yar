rule k2319_1a1b56b9c8800b32 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=k2319.1a1b56b9c8800b32"
    cluster         = "k2319.1a1b56b9c8800b32"
    cluster_size    = "20"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "kryptik script adinject"
    md5_hashes      = "['94c3958f2740db84ab674617dc836125eeecf015','ac061c810cedec80b140c584fc8c4334496d8d76','f43f40af87748f41d88eb0c4c7fbc163c58ac0fb']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=k2319.1a1b56b9c8800b32"

  strings:
    $hex_string = "break};for(var B9Z in O3F9Z){if(B9Z.length===(47.40E1<(0xA8,1.25"

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}