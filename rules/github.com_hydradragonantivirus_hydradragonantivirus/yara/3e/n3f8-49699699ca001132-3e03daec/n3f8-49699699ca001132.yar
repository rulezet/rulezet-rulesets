rule n3f8_49699699ca001132 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=n3f8.49699699ca001132"
    cluster         = "n3f8.49699699ca001132"
    cluster_size    = "4"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180911"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "smsreg inoco andr"
    md5_hashes      = "['27feba2646e058f04505091197bb1710156d1adb','293eabbf57086dc8157db7696cab43f64b5123ed','3863c8aaee4f0e1989a91d632eb06e3f4cacb825']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=n3f8.49699699ca001132"

  strings:
    $hex_string = { ab e5 ae 9a e4 b8 ba e6 88 90 e4 ba ba e5 bd b1 e7 89 87 ef bc 8c e7 a6 81 e6 ad a2 e6 9c aa e6 88 90 e5 b9 b4 e4 ba ba e8 a7 82 e7 9c 8b e3 80 82 00 02 31 39 00 03 31 39 32 00 0c 31 39 32 2e }

  condition:
    filesize > 262144 and filesize < 1048576
    and $hex_string
}