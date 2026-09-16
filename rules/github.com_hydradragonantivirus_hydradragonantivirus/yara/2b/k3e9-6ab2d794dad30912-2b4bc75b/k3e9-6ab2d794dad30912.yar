rule k3e9_6ab2d794dad30912 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e9.6ab2d794dad30912"
    cluster      = "k3e9.6ab2d794dad30912"
    cluster_size = "11"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "outbrowse nsis unwanted"
    md5_hashes   = "['3bfe8ad2eabef9aaf116fff7b5e4ff12','8197fc4f1bec37fc64e0efae4533d971','f09820368c3088bfef1a19e09030b596']"

  strings:
    $hex_string = { 3a 02 92 a5 96 6f a2 d9 c9 d0 67 84 36 e3 0b 7a cf 6a d6 8d 14 22 be 8f f1 0f b0 2c a0 89 38 f5 6b 46 10 59 5e d1 8e dd 44 3f 5b 7e 1a da 4f 16 ea a9 de 1d 42 d3 56 2e 65 a6 3c 73 47 30 93 1f }

  condition:
    filesize > 262144 and filesize < 1048576
    and $hex_string
}