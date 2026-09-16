rule k2321_0319cc22d3a30932 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k2321.0319cc22d3a30932"
    cluster      = "k2321.0319cc22d3a30932"
    cluster_size = "12"
    filetype     = "application/gzip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "hupigon backdoor razy"
    md5_hashes   = "['0724cc491a20c53ff8eb76b9b6fa9140','126b824f2213a6862ddca4e2c69cbb25','f20206158b5b245303eb5eec937f3d10']"

  strings:
    $hex_string = { f7 c1 24 9d 0a 59 6f 9e 37 6b 3c 51 33 1a 4a fc 34 a2 c5 5f 3d f3 76 a8 d6 42 99 92 b7 a0 5a 9f 43 62 f5 95 b3 29 78 69 77 e2 a1 b8 44 c7 2f d9 e1 e9 d5 1e de 8e fb cf f0 79 0b bd a3 35 2d 13 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}