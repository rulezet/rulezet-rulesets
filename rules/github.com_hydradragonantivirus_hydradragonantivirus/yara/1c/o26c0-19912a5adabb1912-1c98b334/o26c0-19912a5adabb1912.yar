rule o26c0_19912a5adabb1912 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=o26c0.19912a5adabb1912"
    cluster         = "o26c0.19912a5adabb1912"
    cluster_size    = "10"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180909"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "graftor kryptik malicious"
    md5_hashes      = "['0431ea05f8a7e6f5d59bd609ea4392699e71765e','4f7b4736b803bb6f995459d09dfcb427dced11ac','fe0401cb59e4dd6ba9b5be3409ce8c01808957c3']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=o26c0.19912a5adabb1912"

  strings:
    $hex_string = { 35 c8 17 93 76 4c 72 87 82 00 7a b4 b0 90 27 63 0f ea 48 12 15 5e 13 b9 dc c1 8f 9b 9a ba 31 7c 26 bf a6 da a5 81 46 43 5f a8 45 00 66 b3 16 3e bd 08 f3 8a 4f 9d c4 06 97 4b 78 07 69 9f ed db }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}