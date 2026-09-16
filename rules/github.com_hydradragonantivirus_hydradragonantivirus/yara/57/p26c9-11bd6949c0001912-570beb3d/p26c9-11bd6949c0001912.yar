rule p26c9_11bd6949c0001912 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=p26c9.11bd6949c0001912"
    cluster         = "p26c9.11bd6949c0001912"
    cluster_size    = "3"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180909"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "razy malicious filerepmalware"
    md5_hashes      = "['7e9185630e23947f41943b471c4d97a534b62dfd','38f424ed48d183f2f17acac7ec9561cd83702c2f','a3af6bbd6db5078e5bc0386d59d2e19e16dfd3e7']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=p26c9.11bd6949c0001912"

  strings:
    $hex_string = { 53 41 b2 03 eb 6d 80 fb 21 74 1c 80 fb 69 74 09 8d 43 91 3c 02 76 10 eb ab 66 83 7e 02 00 c6 85 70 0d 01 00 01 75 9d 44 0f b6 d3 44 89 54 24 40 84 db 74 90 33 db 4c 8d 0d 57 0a fe ff e9 49 01 }

  condition:
    filesize > 4194304 and filesize < 16777216
    and $hex_string
}