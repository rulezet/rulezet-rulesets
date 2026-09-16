rule k26c0_614f2a29c0010b32 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=k26c0.614f2a29c0010b32"
    cluster         = "k26c0.614f2a29c0010b32"
    cluster_size    = "4"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "malicious heuristic attribute"
    md5_hashes      = "['0f66d65733803daee42746d451eb9a3a86ab2ee6','5e71beefd4b25f2f0a36ef18d8e471f6961a8eb4','4250601a9403ca8a4f586c502260266531a4c51b']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=k26c0.614f2a29c0010b32"

  strings:
    $hex_string = { 4f 75 74 70 75 74 41 74 74 72 69 62 75 74 65 00 25 05 57 72 69 74 65 46 69 6c 65 00 4b 45 52 4e 45 4c 33 32 2e 64 6c 6c 00 00 0e 02 4d 65 73 73 61 67 65 42 6f 78 41 00 55 53 45 52 33 32 2e 64 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}