rule k2321_2b14ad6d949b0b12 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k2321.2b14ad6d949b0b12"
    cluster      = "k2321.2b14ad6d949b0b12"
    cluster_size = "16"
    filetype     = "application/gzip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171117"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "tinba emotet zusy"
    md5_hashes   = "['044054aa95a147e284a2cabf34be56b8','0ff7aa5b24f968dfdb7a174647f4ed28','fd607545cf46e765c4c65eeafc42c351']"

  strings:
    $hex_string = { fd f4 d3 3d a7 4f ff 6c 6e 68 38 7f e1 c2 e7 9f 7d f6 f2 cb 2f 6f dc b0 a1 8d cf 2b 59 4c c4 17 04 0f b5 5c 1e a8 d5 82 72 06 9d 96 9c 99 41 0f f1 50 39 3e 34 94 e8 4e 5b 80 8b 51 fa e0 6e 31 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}