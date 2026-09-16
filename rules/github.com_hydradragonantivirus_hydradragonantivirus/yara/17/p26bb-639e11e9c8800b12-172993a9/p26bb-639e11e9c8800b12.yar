rule p26bb_639e11e9c8800b12 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=p26bb.639e11e9c8800b12"
    cluster         = "p26bb.639e11e9c8800b12"
    cluster_size    = "24"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180909"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "attribute crack engine"
    md5_hashes      = "['03975174232f802df427617e85d332ee9dcc5f33','7fd74046ed77bc5da52997a9afc16a470b46128b','bbbc48f2aaf09c56e6bec05292ad28e8396a0bb2']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=p26bb.639e11e9c8800b12"

  strings:
    $hex_string = { 44 ba 69 93 80 c2 19 28 43 18 06 83 95 29 86 04 42 dc 11 c0 70 13 0d 55 77 5d a7 3e 41 9a 7e bd 98 25 9e 53 30 b1 22 1f 65 e4 e5 6d 2c ae 62 92 f4 72 ac 90 4f 01 97 8d d5 58 b8 5a d1 66 f0 c1 }

  condition:
    filesize > 4194304 and filesize < 16777216
    and $hex_string
}