rule k26bb_7a9243d9c2200b12 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=k26bb.7a9243d9c2200b12"
    cluster         = "k26bb.7a9243d9c2200b12"
    cluster_size    = "102463"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "generickd malicious eikqad"
    md5_hashes      = "['5e44a2863aadaddd7e97f56d6644ae1a85c94974','4f9810c69eb5ce628859c69511b0a0f67c48e2a5','114b4d5a0141986bacee1d36828b59bfc5b9ca3c']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=k26bb.7a9243d9c2200b12"

  strings:
    $hex_string = { c9 01 89 4e 08 eb d9 8b 4c 24 04 a1 c8 3e 42 00 56 33 f6 83 f9 20 73 34 39 35 cc 3e 42 00 76 2c 8d 50 08 57 8b 02 a8 06 75 12 33 ff 47 d3 e7 85 7a fc 74 04 0c 01 eb 02 24 fe 89 02 46 81 c2 18 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}