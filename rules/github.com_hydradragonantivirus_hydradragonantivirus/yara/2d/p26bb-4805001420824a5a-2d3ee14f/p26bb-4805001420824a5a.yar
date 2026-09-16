rule p26bb_4805001420824a5a {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=p26bb.4805001420824a5a"
    cluster         = "p26bb.4805001420824a5a"
    cluster_size    = "3"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180909"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "malicious tofsee backdoor"
    md5_hashes      = "['86ebd25da4a1bf78f87d1682e3ecedafb604097c','fb2edf647a8606978fb547ed4b5b1df1cf0507e5','1a3d97e620f1aec301e74c2f975d4d7bc640ad21']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=p26bb.4805001420824a5a"

  strings:
    $hex_string = { 16 a5 78 98 27 22 8d ec 58 e5 3a 91 df 43 30 92 d7 1f be d1 a7 40 b9 8e e6 23 9c 15 b7 4c 57 31 49 ca ac 45 74 5c 96 f9 01 53 1c 37 02 c5 c1 9f 4f 52 84 b1 10 05 32 06 94 a3 47 56 ae fa b0 9e }

  condition:
    filesize > 4194304 and filesize < 16777216
    and $hex_string
}