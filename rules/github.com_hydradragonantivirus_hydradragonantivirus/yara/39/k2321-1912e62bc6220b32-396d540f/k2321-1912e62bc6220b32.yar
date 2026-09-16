rule k2321_1912e62bc6220b32 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k2321.1912e62bc6220b32"
    cluster      = "k2321.1912e62bc6220b32"
    cluster_size = "5"
    filetype     = "application/gzip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "mikey nsismod siggen"
    md5_hashes   = "['0735d489c693316de803934dffca3673','3fd2836451364decd0b4083cbd8ca17d','f0f87885b0d3768545f7cacc9ce2aba1']"

  strings:
    $hex_string = { a6 9a 7b 07 7a 8d 2b 0d d7 37 93 05 d6 63 9d cf 3f 88 5f 71 f8 9e 6b 08 a9 67 bf aa 0c 98 87 de 34 be 57 a7 31 f3 29 e0 0f 6f 72 2d c2 97 51 33 da 2a fb cd e3 8e 85 ec 75 a5 69 d8 13 74 16 11 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}