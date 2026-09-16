rule k2321_292d1962d9eb1932 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k2321.292d1962d9eb1932"
    cluster      = "k2321.292d1962d9eb1932"
    cluster_size = "4"
    filetype     = "application/gzip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "vobfus razy vbkrypt"
    md5_hashes   = "['30d57a9067cfc1869e7bebe8c6ec3e62','32b46ebd6e85835fa07d725f83020d4e','e5c2d183b3d6c3c7e02e28770d44bfa9']"

  strings:
    $hex_string = { 5e 30 19 86 b5 ab 22 7c 40 a5 19 c0 34 4f a9 f5 38 08 5c e2 9a bc 21 85 4a 4b f2 ce f3 8c d8 8e ed 60 57 a6 27 c4 b6 66 82 5d 99 96 b7 97 6b d9 8d eb 6a 72 dd 59 47 2f 15 17 9c 43 2c fa c8 cb }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}