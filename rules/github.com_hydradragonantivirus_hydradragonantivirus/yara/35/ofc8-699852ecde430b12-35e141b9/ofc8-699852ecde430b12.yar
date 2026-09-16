rule ofc8_699852ecde430b12 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=ofc8.699852ecde430b12"
    cluster         = "ofc8.699852ecde430b12"
    cluster_size    = "4"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180909"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "riskware smsreg androidos"
    md5_hashes      = "['b65942b4661741c469f047876f4cf4e23103ca7f','6f909927ced898c92b21d405a6374c1409bd3650','f32255f02c0873f1d56f503c117a3692f075a6f3']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=ofc8.699852ecde430b12"

  strings:
    $hex_string = { 75 9f d9 d4 87 9e 4a bb 4d b7 a8 55 7a b8 0b 1c f0 28 70 d3 b6 9b da d0 e5 0f ce 26 84 d1 18 4f f8 00 10 5d ae 2a 89 13 73 01 58 27 d7 25 e3 3a d8 d6 9d 32 98 8c a3 c5 f7 d5 c4 df be 1d 86 29 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}