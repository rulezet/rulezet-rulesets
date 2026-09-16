rule k2321_293a4d4bdaabd932 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k2321.293a4d4bdaabd932"
    cluster      = "k2321.293a4d4bdaabd932"
    cluster_size = "4"
    filetype     = "application/gzip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "ccpk mira icgh"
    md5_hashes   = "['18e6d585bc78c0ec724337f4e10983d0','c18a55f4043195bf26ae44c5c35b2afa','f2a4a2833dc6a15bbdc50758099d7001']"

  strings:
    $hex_string = { 3b 4d 5a 9e 21 7c 0f d6 cb 32 66 ab 5c a5 d8 2a 7d d1 e4 c5 4b 8a e8 90 33 a7 59 d9 cf 02 4e 85 20 f1 0a 98 35 b7 01 cc c6 d5 71 60 f6 aa 16 cc 1a a8 9d 40 e0 0c 89 8c c0 19 88 43 06 b3 6d a4 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}