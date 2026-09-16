rule p26d7_4b24ea48c0000916 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=p26d7.4b24ea48c0000916"
    cluster         = "p26d7.4b24ea48c0000916"
    cluster_size    = "255"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180909"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "gamemodding malicious gamehack"
    md5_hashes      = "['757cfd1b569b1daf833c8d76d200e0d5f4768d59','b277e4c8429e5c5a47eac8b5a7d43d649888265d','ae18b97cf5f34462df2abf64bb70e0024e9e6d2e']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=p26d7.4b24ea48c0000916"

  strings:
    $hex_string = { d6 fc ff 9f d3 fb fe 97 cf fa ff 85 bb e5 ff 4a 6b 84 ff 15 1f 27 ff 01 02 02 fd 00 00 00 e8 0b 11 17 83 25 40 54 24 05 09 0d 6a 01 02 03 e6 20 3f 55 ff 51 a1 de ff 56 b3 f8 ff 52 b1 f7 ff 4e }

  condition:
    filesize > 4194304 and filesize < 16777216
    and $hex_string
}