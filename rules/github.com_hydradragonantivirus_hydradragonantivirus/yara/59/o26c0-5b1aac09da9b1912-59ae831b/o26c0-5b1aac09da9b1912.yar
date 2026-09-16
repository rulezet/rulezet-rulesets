rule o26c0_5b1aac09da9b1912 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=o26c0.5b1aac09da9b1912"
    cluster         = "o26c0.5b1aac09da9b1912"
    cluster_size    = "18"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180909"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "graftor downloadhelper malicious"
    md5_hashes      = "['bd2ceafa64e93a1e97f2959321901972d8b037fb','d6ae72b16db51634f006ba5071d4b9e0431c2fe9','26a989372a78f014dce1a124a0c303a6f4143786']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=o26c0.5b1aac09da9b1912"

  strings:
    $hex_string = { 32 52 44 53 97 4e 63 dc 88 d9 2b 2e 72 02 ff 0e 3d 00 ec 27 61 2f 2d 81 98 b3 6e c8 7c 7f 07 e5 42 fc bc 8c a1 fe 55 51 c5 d2 9e 18 68 0f d8 b9 6c cd 7a 00 ab 82 4f d5 79 19 04 24 4c 4b 0d f8 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}