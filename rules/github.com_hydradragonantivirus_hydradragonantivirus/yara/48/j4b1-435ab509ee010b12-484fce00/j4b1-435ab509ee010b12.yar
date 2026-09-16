rule j4b1_435ab509ee010b12 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=j4b1.435ab509ee010b12"
    cluster      = "j4b1.435ab509ee010b12"
    cluster_size = "245"
    filetype     = "video/mp4"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171117"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = ""
    md5_hashes   = "['003ddd1c7d719d0f2e0133f1f7f26d9f','006a21e32ad660586e7dd517234b3386','13534cd47e1a8a03c594f53b64ad20a7']"

  strings:
    $hex_string = { 02 00 0a af 52 00 0b 8a 24 00 0c 42 38 00 0d 29 77 00 0d fc 75 00 0e d4 12 00 0f b3 ce 00 10 82 a1 00 11 3e fa 00 11 d8 26 00 12 cd 45 00 13 c4 a6 00 14 e0 9d 00 15 f2 f0 00 16 e2 4b 00 17 aa }

  condition:
    filesize > 4096 and filesize < 16384
    and $hex_string
}