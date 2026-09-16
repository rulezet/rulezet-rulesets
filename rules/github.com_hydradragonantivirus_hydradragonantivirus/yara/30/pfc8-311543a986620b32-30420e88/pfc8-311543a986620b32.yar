rule pfc8_311543a986620b32 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=pfc8.311543a986620b32"
    cluster      = "pfc8.311543a986620b32"
    cluster_size = "124"
    filetype     = "application/zip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "androidos riskware smsreg"
    md5_hashes   = "['017034ea1d96cc17d3367c0ba8147e09','04bab4fb0a6da370d7ea8d35e5346435','228282d4c5896f142a54453928f8e3db']"

  strings:
    $hex_string = { b0 da 00 75 53 12 59 fc cb 04 30 a0 a4 74 18 80 72 4b 77 67 b1 32 27 bb e9 60 a1 bf 05 51 5a 64 10 01 50 d2 9a f9 1e 73 3a 90 31 a3 7e 92 af 8e 38 d9 ef 87 fa 88 15 d0 cd 28 47 23 ce 4f 95 0c }

  condition:
    filesize > 4194304 and filesize < 16777216
    and $hex_string
}