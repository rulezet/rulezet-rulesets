rule k2321_0917688986220b12 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k2321.0917688986220b12"
    cluster      = "k2321.0917688986220b12"
    cluster_size = "15"
    filetype     = "application/gzip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171118"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "brontok email pazetus"
    md5_hashes   = "['03ed05d39b2de67e5a0b392edf8be097','18a07827ae3650bf9c6afe62f2ac3c8e','d82f22da9b73edc72de19770dc84d316']"

  strings:
    $hex_string = { 15 bb 82 44 6d f1 21 fc d1 7b e2 1e a8 ec c1 46 0d 26 48 30 40 b8 08 7a f4 fe ea e5 83 ac c6 60 84 6a 52 72 9d b9 97 36 cb f0 20 85 29 4c ee e0 a1 9b 5a f1 27 12 db e9 b1 54 ed c4 2e 93 b5 38 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}