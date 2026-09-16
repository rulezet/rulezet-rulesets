rule o3e9_0b9349b65852e392 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=o3e9.0b9349b65852e392"
    cluster      = "o3e9.0b9349b65852e392"
    cluster_size = "260"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171111"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "installmonster installmonstr malicious"
    md5_hashes   = "['0077e961bef13ea40a037aace303e732','014635b622004a1e8a8467b0031a1af9','0ad6adc172b01eda4816066137eb2a39']"

  strings:
    $hex_string = { ed b9 a0 7d 6a 1c f5 f9 72 83 0a 31 88 ef ff e7 29 1a 3e df 8d 38 7a 3c 69 1d a3 e2 36 d1 64 54 9e 06 d9 8e c3 e4 da a4 f6 95 77 bf e8 c8 b1 d2 08 13 52 7f 30 2f 47 4f 39 49 1e 65 11 19 21 a6 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}