rule n3f8_53b852b49aeb1112 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=n3f8.53b852b49aeb1112"
    cluster         = "n3f8.53b852b49aeb1112"
    cluster_size    = "5"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180911"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "androidos vmvol piom"
    md5_hashes      = "['4b4008970dbcf3056218a4b3a2a5a818d2f77e12','7d8ddfde11adbdba83a45ec7ebbae2233a585c9d','c1aefaaf7cead871df602e316bc96f1e851715d1']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=n3f8.53b852b49aeb1112"

  strings:
    $hex_string = { 02 0b 13 00 00 13 03 9d 01 82 13 00 00 14 03 84 01 5c 0f 00 00 16 03 cc 02 ad 10 00 00 17 03 61 04 26 0c 00 00 17 03 3a 05 6c 0f 00 00 17 03 61 04 42 11 00 00 18 03 78 05 11 0d 00 00 18 03 74 }

  condition:
    filesize > 262144 and filesize < 1048576
    and $hex_string
}