rule k2321_19159fa9ca000b12 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k2321.19159fa9ca000b12"
    cluster      = "k2321.19159fa9ca000b12"
    cluster_size = "96"
    filetype     = "application/gzip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "nimnul vjadtre small"
    md5_hashes   = "['0aa43a90a7b36b220417ea3ca00a55f4','0b6712dabeb4d42872f6846b4d220b5c','3eca35a0113f12f763c33ef5c4cdf20e']"

  strings:
    $hex_string = { 5a d9 a8 29 43 61 ed 98 70 68 f7 69 71 5e 67 11 36 13 8f 83 33 97 92 07 3e 25 31 f2 9a 1d b0 7d 12 a8 32 2a 76 b8 87 c2 64 89 aa 5c 0d 2e e7 6b 09 27 d7 ad 78 a6 ff d4 24 6d 21 c9 7e d0 a9 f5 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}