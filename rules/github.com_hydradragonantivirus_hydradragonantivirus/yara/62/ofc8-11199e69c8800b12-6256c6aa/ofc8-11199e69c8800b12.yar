rule ofc8_11199e69c8800b12 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=ofc8.11199e69c8800b12"
    cluster         = "ofc8.11199e69c8800b12"
    cluster_size    = "313"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180909"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "shedun androidos revo"
    md5_hashes      = "['5495725f67131f868f777bcca4ee6351a66fa11c','591d3a4dab47743055156d91f02e3865574076f9','18519a440e6d0ba21c2c3af98644f635f1daa741']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=ofc8.11199e69c8800b12"

  strings:
    $hex_string = { 6a 74 52 4e 53 00 01 02 03 05 2b 5a 75 80 76 5b 2d 04 19 7c d2 fc d4 7d 1a 6e ed fe fa f6 ee 71 10 b1 b3 11 c4 fb ef b6 8e 82 c7 13 b0 eb 15 16 73 ea b4 70 c2 1e 1c c0 e8 c3 0c 0b 1f 7b 23 21 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}