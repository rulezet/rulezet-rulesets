rule o26bb_698d2f0dcceb0b12 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=o26bb.698d2f0dcceb0b12"
    cluster         = "o26bb.698d2f0dcceb0b12"
    cluster_size    = "36"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180909"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "kuzitui filerepmalware kuaizip"
    md5_hashes      = "['c703d1b4f22fa4a157e8bcf707f08fbfafb36bbf','de31bc469bbf6e08349a00f2f49e24c818238633','1f109120df9c57bf5914a83cae48afb2d795aa0d']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=o26bb.698d2f0dcceb0b12"

  strings:
    $hex_string = { 1c 6d 13 00 52 50 68 20 72 60 00 56 6a 18 e8 1d 97 fc ff 83 c4 14 85 f6 75 17 33 c0 eb 26 8b 4d 08 51 e8 e9 a9 fe ff 83 c4 04 5f 5e 5b 8b e5 5d c3 8b c6 8d 50 01 8a 08 40 84 c9 75 f9 2b c2 25 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}