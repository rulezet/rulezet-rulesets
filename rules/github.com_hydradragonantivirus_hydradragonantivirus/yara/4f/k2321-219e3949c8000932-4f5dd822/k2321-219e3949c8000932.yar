rule k2321_219e3949c8000932 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k2321.219e3949c8000932"
    cluster      = "k2321.219e3949c8000932"
    cluster_size = "5"
    filetype     = "application/gzip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171124"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "nitol fdld ddos"
    md5_hashes   = "['09c4fc224b4ae864688f803263260b22','66d2a5a5475e94b04a2472bec8cfc69f','d3c0991a823224675f54c5ca72bd2437']"

  strings:
    $hex_string = { fd 3c 66 9f 62 93 d3 88 83 2a 3b a6 b2 2d 79 3a b9 42 af e7 a6 ee 7a a1 c8 19 67 b3 e1 aa 94 0a 10 5d 16 af f8 4b fb 03 a5 09 bb 11 29 6a 12 33 86 5e 7d 98 ae 40 e3 24 6d 5a 2f a2 8e 22 26 14 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}