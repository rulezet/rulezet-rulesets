rule k2321_0915698986220b12 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k2321.0915698986220b12"
    cluster      = "k2321.0915698986220b12"
    cluster_size = "5"
    filetype     = "gzip compressed data"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171118"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "brontok email pazetus"
    md5_hashes   = "['0ddbd8f08842ce3f0fc2bccbdd30d8c3','25759b0b75eacd4ad482fdc408d3b0fe','fd171ef08b30b03dfcd247a72c10e785']"

  strings:
    $hex_string = { d4 e1 d7 3a 7d d6 18 87 31 2d b1 01 7e 1e 33 34 da dc e0 30 7f 04 ba c3 49 70 2f 14 ce a3 ee af be 35 af 11 5d 7b 47 65 f7 d3 21 99 57 0e d9 1c e9 5b 42 27 8f 81 c7 83 ca 85 02 2e b7 a5 4c d1 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}