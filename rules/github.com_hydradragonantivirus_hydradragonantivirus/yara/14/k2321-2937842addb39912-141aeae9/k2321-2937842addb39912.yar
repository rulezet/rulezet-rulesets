rule k2321_2937842addb39912 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k2321.2937842addb39912"
    cluster      = "k2321.2937842addb39912"
    cluster_size = "8"
    filetype     = "application/gzip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "installm unwanted downware"
    md5_hashes   = "['0aca4c4c92f717be7e09682e87162b5c','3f145c1b08aac378414d3c5019b41690','d9f4320f59247899fee23a94c237d55b']"

  strings:
    $hex_string = { bf 8f 40 46 cb 3d 20 60 ca f7 6b 4f 0f d1 28 8d 05 a8 03 bd 86 42 2b 6a e7 c6 f4 a1 fa 0c 9d 71 22 02 2d 82 eb 01 53 a8 79 ec ad b1 4c 30 67 f8 de 7b 5b 75 ea 80 48 59 54 b0 26 99 f9 43 1d 4d }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}