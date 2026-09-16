rule k2321_0ac998561e6e4cba {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k2321.0ac998561e6e4cba"
    cluster      = "k2321.0ac998561e6e4cba"
    cluster_size = "9"
    filetype     = "application/gzip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171118"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "tinba zusy backdoor"
    md5_hashes   = "['189564ce19d2d9a09379af9c39b2e201','33b6cab1c36cb3c6fba58264064ee157','d90bd82fed8a33112b685dd3579e70d5']"

  strings:
    $hex_string = { 72 c5 38 13 97 2f 58 a6 a3 43 84 e7 f9 9d ef 03 c6 f2 c3 3d 88 74 f4 54 f1 79 50 22 0f dc 62 45 2b 44 6e 11 8f de 24 5c 08 a1 98 27 17 96 52 85 25 78 d2 27 94 db 14 9e 68 29 a0 ac 20 0d 60 90 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}