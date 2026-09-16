rule n3f8_492d98adc6421132 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=n3f8.492d98adc6421132"
    cluster         = "n3f8.492d98adc6421132"
    cluster_size    = "20"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180911"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "androidos smssend backdoor"
    md5_hashes      = "['787aaf1ceb45cd6474ad6b891d1ea720d0bff7a9','c8841708879a3e2a08a50f94a50d877673974f35','6aff35d38c008c935f5ae2ccb3081699295aaee8']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=n3f8.492d98adc6421132"

  strings:
    $hex_string = { 72 73 65 72 46 61 63 74 6f 72 79 3b 00 03 4c 75 61 00 07 4c 75 61 54 65 6c 6c 00 01 4d 00 0c 4d 41 4e 55 46 41 43 54 55 52 45 52 00 11 4d 41 58 49 4d 55 4d 5f 50 4f 4f 4c 5f 53 49 5a 45 00 02 }

  condition:
    filesize > 262144 and filesize < 1048576
    and $hex_string
}