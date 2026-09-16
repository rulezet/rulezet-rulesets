rule o3e9_2b627c66919b1912 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=o3e9.2b627c66919b1912"
    cluster      = "o3e9.2b627c66919b1912"
    cluster_size = "1488"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "small keylogger riskware"
    md5_hashes   = "['001317652cf78e080729ba525aa5ee32','0036eb2219807d093140443b427c5291','03421ebd67c9775314b8cb40366384b8']"

  strings:
    $hex_string = { a0 bd 5c 1a c2 d2 8f 1d 7e bc 39 9f 58 36 0a 66 4f c4 61 55 fd cf a8 91 01 b7 25 d4 17 29 80 d6 3e 50 dd 7f 48 5d 43 d1 65 e0 57 71 31 1c a7 37 d0 00 3c bb e5 ab fa c5 e9 f0 22 62 6d 9d da 24 }

  condition:
    filesize > 4194304 and filesize < 16777216
    and $hex_string
}