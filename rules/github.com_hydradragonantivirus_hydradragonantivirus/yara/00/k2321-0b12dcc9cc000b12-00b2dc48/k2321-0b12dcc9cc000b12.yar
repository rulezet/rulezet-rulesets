rule k2321_0b12dcc9cc000b12 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k2321.0b12dcc9cc000b12"
    cluster      = "k2321.0b12dcc9cc000b12"
    cluster_size = "9"
    filetype     = "PE32 executable (GUI) Intel 80386"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171117"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "rincux ddos stormattack"
    md5_hashes   = "['06db062ebdb36b02532c6dd97c225daa','09b7db48489793cceda0a7c1fe233a40','fb3833627432b5120aaf5170721c1c60']"

  strings:
    $hex_string = { 34 b0 14 d9 71 cf 83 9e 17 8d b5 62 1e 74 be 6d 4b 43 2f 38 a5 c5 73 7e 69 f1 9c 0d 36 c0 46 ee c4 e3 7b 88 b8 c2 dc 41 c7 e2 c6 c9 7c a7 10 df 6e e7 bf f1 76 bb dd 40 aa 22 e0 4c 60 f4 ef ae }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}