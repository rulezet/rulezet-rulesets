rule k2321_0b929cc9cc000912 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k2321.0b929cc9cc000912"
    cluster      = "k2321.0b929cc9cc000912"
    cluster_size = "5"
    filetype     = "application/gzip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "rincux ddos stormattack"
    md5_hashes   = "['3c188e9d81b73d3cfde2706c9df9f9e9','53ab5ee89cf1f9a3e8c754961740d869','f27d725bc9cc9f98a830e0062762b53c']"

  strings:
    $hex_string = { 6b 1f 95 42 b5 d9 e2 de 60 b6 ee d1 d3 1a d1 9b b9 7b 0c 2c 93 cd 84 51 6d 36 a1 34 22 b1 1c 85 91 40 e4 ef a2 53 24 73 dc 9f aa 41 b6 c8 20 14 cb 7c 04 da 03 03 79 7a 67 ae 38 d6 56 0a b2 4f }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}