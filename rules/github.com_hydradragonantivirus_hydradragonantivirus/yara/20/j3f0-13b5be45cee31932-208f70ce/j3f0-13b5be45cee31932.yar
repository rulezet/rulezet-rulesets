rule j3f0_13b5be45cee31932 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=j3f0.13b5be45cee31932"
    cluster      = "j3f0.13b5be45cee31932"
    cluster_size = "6"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "razy malicious genericrxci"
    md5_hashes   = "['7f259fc5ba6ccaaaf2ba633b843e7159','970648a5648eb511045809c7b64f234d','bef89563d0fb4e1205167246fbd25cdb']"

  strings:
    $hex_string = { e4 8b 4d 84 03 48 3c 8b 45 f0 0f b7 40 10 8d 44 01 18 89 45 e8 8b 45 91 2b 85 50 ff ff ff 50 6a 00 8b 45 84 03 85 50 ff ff ff 50 e8 cf 07 00 00 83 c4 0c 8d 45 f4 50 6a 04 0f b6 45 88 6b c0 28 }

  condition:
    filesize > 4096 and filesize < 16384
    and $hex_string
}