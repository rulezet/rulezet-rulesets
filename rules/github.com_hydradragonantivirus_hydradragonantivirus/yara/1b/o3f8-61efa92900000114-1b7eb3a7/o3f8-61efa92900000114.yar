rule o3f8_61efa92900000114 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=o3f8.61efa92900000114"
    cluster         = "o3f8.61efa92900000114"
    cluster_size    = "38"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180909"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "hiddad androidos andr"
    md5_hashes      = "['f23e8dfb2db41da3b166acf259460165d9c57a3c','c87c34efc9659680c29d70d0a80efa2729b7dabd','9c218190411410c3e3c2d00717b7f5d7ed3a5b0f']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=o3f8.61efa92900000114"

  strings:
    $hex_string = { 6f 75 74 20 6f 66 20 72 61 6e 67 65 00 08 3b 20 73 65 63 75 72 65 00 56 3b 5c 73 2a 28 3f 3a 28 5b 61 2d 7a 41 2d 5a 30 2d 39 2d 21 23 24 25 26 27 2a 2b 2e 5e 5f 60 7b 7c 7d 7e 5d 2b 29 3d 28 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}