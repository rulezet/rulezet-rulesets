rule k2321_09617922d9eb1912 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k2321.09617922d9eb1912"
    cluster      = "k2321.09617922d9eb1912"
    cluster_size = "5"
    filetype     = "application/gzip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171121"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "vobfus conjar autorun"
    md5_hashes   = "['0a405c12fe590a0b44ce68ad464c88c6','2d25a5a811b748a7dd45d1b8c6cda861','dbc8beb3b21d4b7ab5d56deeb6299824']"

  strings:
    $hex_string = { 14 41 da 2f cb 5f c5 b0 6c ef 31 e7 50 b7 7b e4 2b 60 7d 9d d9 89 8e 16 9a 40 e5 76 f9 2e 06 4e af 3e 66 0f 7e 7b f2 07 94 34 10 01 51 28 49 b5 86 54 69 f5 a5 4e 26 58 21 1e 7a 3c 26 d1 7f 47 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}