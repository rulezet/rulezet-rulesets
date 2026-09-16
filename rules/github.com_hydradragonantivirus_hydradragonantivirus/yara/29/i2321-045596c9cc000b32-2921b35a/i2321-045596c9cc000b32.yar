rule i2321_045596c9cc000b32 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=i2321.045596c9cc000b32"
    cluster      = "i2321.045596c9cc000b32"
    cluster_size = "6"
    filetype     = "application/gzip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "cosmicduke backdoor razy"
    md5_hashes   = "['126b2c657f4cfe88490e3bcc00076cde','19bedf57a90950812f2d73b27035a183','4930d2e655bbaeee3a0e2fcc975149d6']"

  strings:
    $hex_string = { 06 85 74 42 cd 26 69 f5 fa ae 43 eb cf 9d 3d b3 bc 51 be fa 7a 7a 76 e2 f0 3d 6b af 64 ff b2 de 0a 61 79 bd 6d f9 9d b6 a5 3f bf 3e d4 2c 7a 7c 5b ac 10 37 62 7f 1a 8f e9 17 bf 1e d3 73 ab a3 }

  condition:
    filesize > 1024 and filesize < 4096
    and $hex_string
}