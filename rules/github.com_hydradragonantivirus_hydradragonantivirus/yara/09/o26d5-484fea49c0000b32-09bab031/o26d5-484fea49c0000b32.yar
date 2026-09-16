rule o26d5_484fea49c0000b32 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=o26d5.484fea49c0000b32"
    cluster         = "o26d5.484fea49c0000b32"
    cluster_size    = "3"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180909"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "razy malicious dangerousobject"
    md5_hashes      = "['4afd9e5a26f4303da850e77cc2af2197fe5dd809','98bffbcdd6d641906256816f54e038bdc5d752ac','0ac6959def48a01185d219ed7eba130c3ad5a008']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=o26d5.484fea49c0000b32"

  strings:
    $hex_string = { 69 54 f8 c0 89 59 66 ef 9a 24 b4 0d 98 99 a6 a8 37 51 95 0a 96 eb 60 e8 9c de ce 0e c2 74 30 2c 9b 6e b7 b3 1b 70 8a 1c c1 e4 9d a7 f0 aa 55 0c a0 c8 72 5a 07 16 18 df 7f 00 7b 7c 92 ca f4 3e }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}