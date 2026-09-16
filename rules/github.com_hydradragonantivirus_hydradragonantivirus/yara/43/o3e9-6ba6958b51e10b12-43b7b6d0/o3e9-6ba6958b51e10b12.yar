rule o3e9_6ba6958b51e10b12 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=o3e9.6ba6958b51e10b12"
    cluster      = "o3e9.6ba6958b51e10b12"
    cluster_size = "372"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "virut virtob classic"
    md5_hashes   = "['01ee2b8e99d173b41ff36e775fbda95e','02ec328abb57dc7f27bb07b87fa1d9ba','15cdee8f5c2d014b99b95fe7bcae2dfb']"

  strings:
    $hex_string = { 33 49 e8 2c ff cd 52 b6 11 51 44 46 fd 80 d1 be c1 a8 2f 09 f6 e2 a2 9e 4f 58 5e 53 47 84 43 5a 94 8b a6 39 3d 19 6f 0c d8 bb 38 a3 de 88 ac df fb 00 27 f4 59 16 12 98 25 01 5d 50 3b 45 5c 95 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}