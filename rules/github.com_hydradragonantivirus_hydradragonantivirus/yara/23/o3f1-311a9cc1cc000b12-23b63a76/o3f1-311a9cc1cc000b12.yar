rule o3f1_311a9cc1cc000b12 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=o3f1.311a9cc1cc000b12"
    cluster      = "o3f1.311a9cc1cc000b12"
    cluster_size = "36"
    filetype     = "application/zip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171123"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "shedun androidos riskware"
    md5_hashes   = "['03b87bcd31f3c4bbd46b959b29b6d2cc','05908b86de33f29eb7d208196da89936','724a972a679a9f5facbba6c806a1fe85']"

  strings:
    $hex_string = { 72 e0 b3 16 5d 00 3f d3 78 e9 f3 73 af 21 de 33 2b 5e cc 05 9a 87 75 fb 79 97 c2 83 bb 4b ac a4 a9 0e c6 14 59 b8 b1 a2 92 d0 c9 3b 19 30 cd cb 25 9f 6e e9 24 0a 18 87 0f 91 db 39 02 51 1f 12 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}