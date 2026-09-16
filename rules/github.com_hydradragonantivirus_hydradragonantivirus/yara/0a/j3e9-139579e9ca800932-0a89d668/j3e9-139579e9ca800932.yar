rule j3e9_139579e9ca800932 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=j3e9.139579e9ca800932"
    cluster      = "j3e9.139579e9ca800932"
    cluster_size = "11"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "zusy zegost trojandownloader"
    md5_hashes   = "['108c5fee681448072ae2781c101d70bf','1c8b8f0d9fbe974cf973c97bff735247','e824df157291e090a6ff4813a00ae5ff']"

  strings:
    $hex_string = { eb 23 42 8b c8 2b ca 85 c9 7e 1a 8b c1 56 8d b2 30 40 40 00 8d 7c 24 10 c1 e9 02 f3 a5 8b c8 83 e1 03 f3 a4 5e 8d 4c 24 0c 51 e8 43 01 00 00 83 c4 04 85 c0 5f 7e 4d b1 2e 38 4c 04 08 74 16 48 }

  condition:
    filesize > 4096 and filesize < 16384
    and $hex_string
}