rule o26c0_5d9d2689c0000b32 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=o26c0.5d9d2689c0000b32"
    cluster         = "o26c0.5d9d2689c0000b32"
    cluster_size    = "435"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180909"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "malicious filerepmalware genkryptik"
    md5_hashes      = "['354536c0359f23fea1d1eb0397e9b8260894a2dc','fdb4de874f249cc84ccdf55ac326a7b8696f2c99','595e2beab3884f1d0153443b8b4c549455902d38']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=o26c0.5d9d2689c0000b32"

  strings:
    $hex_string = { 88 0e 8d 2c 80 8b 46 10 03 ed 89 6e 04 8b dd 8a 00 0f be f8 83 ef 30 0f af df 3c 30 7c 39 3c 3a 7d 35 85 ff 74 1a 84 c9 75 2d 83 c8 ff 33 d2 f7 f7 3b c5 72 22 8b 4e 08 8b c3 f7 d0 3b 01 72 17 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}