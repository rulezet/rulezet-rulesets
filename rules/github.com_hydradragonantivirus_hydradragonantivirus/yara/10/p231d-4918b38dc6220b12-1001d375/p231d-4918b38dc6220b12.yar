rule p231d_4918b38dc6220b12 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=p231d.4918b38dc6220b12"
    cluster         = "p231d.4918b38dc6220b12"
    cluster_size    = "10"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180909"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "riskware smspay heepay"
    md5_hashes      = "['eda8b3f60426ab1693d57db26bcc27a2bd232db6','c61d19c9a549f4f3a16ac1d42f36d1969a10daf2','2cc76afe45a66c6ff2bb7e6708d7b171fea3f4da']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=p231d.4918b38dc6220b12"

  strings:
    $hex_string = { 4a f9 87 c0 40 7f 0f f8 67 3e 17 bd 9a 63 2a 74 8d e7 c7 9f 5d e0 aa 57 be 09 7a d8 1f 0e c9 94 0b 53 cc c4 b2 27 a6 99 29 19 62 d1 1d a5 b5 72 fc 61 48 ad d6 8e 22 b6 6a 0a 3a 1c 02 7c ef c5 }

  condition:
    filesize > 4194304 and filesize < 16777216
    and $hex_string
}