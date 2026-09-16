rule o3f8_43aa6a01c0001132 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=o3f8.43aa6a01c0001132"
    cluster         = "o3f8.43aa6a01c0001132"
    cluster_size    = "278"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180909"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "androidos smsthief andr"
    md5_hashes      = "['8c29fc01046e4ca3afb91920967010ed0bbd0cc7','d0f108b999b466aa6c8e8c0356a4da366841f488','9c1b2fa2a3e26cfecb1197b547238d502275f6b2']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=o3f8.43aa6a01c0001132"

  strings:
    $hex_string = { 09 4b 45 59 5f 54 49 54 4c 45 00 07 4b 53 43 35 36 30 31 00 18 4b 65 79 45 76 65 6e 74 20 6d 61 79 20 6e 6f 74 20 62 65 20 6e 75 6c 6c 00 08 4b 65 79 77 6f 72 64 73 00 01 4c 00 05 4c 41 52 47 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}