rule ofc8_3111a64bc6220b12 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=ofc8.3111a64bc6220b12"
    cluster         = "ofc8.3111a64bc6220b12"
    cluster_size    = "251"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180909"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "smspay riskware shedun"
    md5_hashes      = "['1307b73c1a4e33c5bae1481ab90d2c5e950310b3','09970768c73dada90d94e23b3bceb908cf1f0f52','8a0473eaeeea169da0f1707270f48bc0986f6a64']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=ofc8.3111a64bc6220b12"

  strings:
    $hex_string = { b4 2e 03 9d 89 c6 bc 06 63 68 b2 f6 7d 0c 3f 67 1f 7f e5 5f d8 a5 39 f0 08 01 52 d7 71 42 e8 ff 5d 1d 98 e6 ad 84 ac 00 56 93 e3 cd d4 dc 54 15 59 32 8c 30 b1 6f 23 38 45 33 bb 75 d1 a1 77 7e }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}