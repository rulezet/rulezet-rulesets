rule k2321_2914ad6d9a9b0b12 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k2321.2914ad6d9a9b0b12"
    cluster      = "k2321.2914ad6d9a9b0b12"
    cluster_size = "5"
    filetype     = "application/gzip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "tinba emotet zusy"
    md5_hashes   = "['01050e69d1437c5998ffe3bddcf35014','2fd6091b18dabedc2c9b959fc0f8f01f','90bdf3b44fe0f14714fa47bb54a70384']"

  strings:
    $hex_string = { 9d 1b c9 9a 18 c6 4a 0f 66 a7 68 b9 91 1a b1 5e ab 54 ca 65 02 f2 f6 ba 3f 23 a0 ad cf f7 99 0c 0e 9b 25 12 0a d4 0a 45 90 46 1d ac 56 e8 95 d2 10 b5 38 52 2d 8a 51 0b 63 35 82 58 8d 30 4e c3 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}