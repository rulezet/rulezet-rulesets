rule k2321_091a5cc9cc000912 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k2321.091a5cc9cc000912"
    cluster      = "k2321.091a5cc9cc000912"
    cluster_size = "8"
    filetype     = "application/gzip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "rincux ddos stormattack"
    md5_hashes   = "['043aae6757c766ab5c3526fcd132563c','1de3a799f85d286d9159708caced9925','fd3456dc8c8f143285ad652ce1bf27bf']"

  strings:
    $hex_string = { 59 4c 20 d7 af 52 35 f8 4f 99 e8 a1 aa b0 ef 2a 54 61 57 40 15 68 45 26 54 05 b9 ca ef a5 0e 2e f3 10 a3 28 84 5f 1b 22 e9 62 09 91 17 4b 70 ed 30 a0 18 6e b6 cf dd d8 df c3 1e 9d 41 ab fb c0 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}