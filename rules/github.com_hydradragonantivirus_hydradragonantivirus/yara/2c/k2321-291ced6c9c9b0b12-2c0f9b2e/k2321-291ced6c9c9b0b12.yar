rule k2321_291ced6c9c9b0b12 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k2321.291ced6c9c9b0b12"
    cluster      = "k2321.291ced6c9c9b0b12"
    cluster_size = "4"
    filetype     = "application/gzip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171117"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "tinba zusy emotet"
    md5_hashes   = "['2c6645f014ccebb3f058dea1a7ee6034','524fd72692c9d1e678264a25b2787895','caeebf20d32d881d43ea1913ea940245']"

  strings:
    $hex_string = { 65 91 ce 02 52 2e 50 37 94 22 c7 c1 79 11 d5 14 f5 c5 8a ba 42 04 7d 59 6d 3e 81 a4 72 86 b8 6a ba a8 61 a6 d0 3c 83 7f 7e 32 07 8d d8 8b bd 19 d3 13 24 dd 22 82 60 a0 4c 2a 45 47 27 e0 b4 cd }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}