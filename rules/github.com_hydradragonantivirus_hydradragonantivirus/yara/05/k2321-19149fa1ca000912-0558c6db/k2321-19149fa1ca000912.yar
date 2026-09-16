rule k2321_19149fa1ca000912 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k2321.19149fa1ca000912"
    cluster      = "k2321.19149fa1ca000912"
    cluster_size = "25"
    filetype     = "application/gzip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "nimnul vjadtre small"
    md5_hashes   = "['0013c88df9ed46ae9fe9bda89b614f64','0a3c29d21fbd8de9ac2ca071943e9133','a425560b67046bd0d7d0902fc3d71630']"

  strings:
    $hex_string = { 4b b5 cb eb 5e a1 b2 ca 6c d6 c1 f3 49 3a 56 1b 03 99 d2 27 88 c6 36 fc d9 5a ab b3 f5 44 67 77 2a 24 1c 62 e7 65 c3 f4 14 11 6d 5b 25 15 39 5d d9 34 8d f0 d5 bd 66 1d 35 fe 46 37 f2 a8 cf de }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}