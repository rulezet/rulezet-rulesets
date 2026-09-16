rule i26c0_69bd33a9c2000b12 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=i26c0.69bd33a9c2000b12"
    cluster         = "i26c0.69bd33a9c2000b12"
    cluster_size    = "734"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "zusy malicious rogue"
    md5_hashes      = "['2eb767b2c6101eb1203d2f6c2998a1d0a64c85cb','2401033797199c3550466caabf9e45d4dece723f','9a202b919550e2d040fb88e26b48e8ac08ec3168']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=i26c0.69bd33a9c2000b12"

  strings:
    $hex_string = { 43 72 65 61 74 65 46 69 6c 65 41 00 00 00 47 65 74 46 69 6c 65 53 69 7a 65 00 00 00 47 65 74 4d 6f 64 75 6c 65 46 69 6c 65 4e 61 6d 65 41 00 00 00 00 47 65 74 50 72 6f 63 65 73 73 48 65 61 70 }

  condition:
    filesize > 1024 and filesize < 4096
    and $hex_string
}