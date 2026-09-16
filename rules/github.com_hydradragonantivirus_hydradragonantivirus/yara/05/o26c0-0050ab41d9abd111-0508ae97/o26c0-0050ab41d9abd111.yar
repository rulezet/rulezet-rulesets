rule o26c0_0050ab41d9abd111 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=o26c0.0050ab41d9abd111"
    cluster         = "o26c0.0050ab41d9abd111"
    cluster_size    = "170"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180909"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "jaik malicious crypt"
    md5_hashes      = "['a4605e5df85c801d8e00c22710cb98b2f73fff04','ad578132f69b7140ba53e0591d9d84b2388581ba','4789ba496e60b2d80460811a2c5dd35bf0999234']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=o26c0.0050ab41d9abd111"

  strings:
    $hex_string = { 01 97 d5 e7 b4 81 37 1c 9e 8b 91 19 77 a2 a9 02 9c a1 7c f8 5f e8 e6 fe 3f 78 53 fa 34 c6 d0 f4 f3 ab 1d 18 67 41 be 12 27 d4 4b 64 89 79 51 af 57 23 d3 84 bb 2f fd de 56 4a e9 b8 f5 50 6d ad }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}