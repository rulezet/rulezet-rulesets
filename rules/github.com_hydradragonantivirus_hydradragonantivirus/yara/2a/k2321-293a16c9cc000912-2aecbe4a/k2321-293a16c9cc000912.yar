rule k2321_293a16c9cc000912 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k2321.293a16c9cc000912"
    cluster      = "k2321.293a16c9cc000912"
    cluster_size = "5"
    filetype     = "application/gzip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "selfdel zbot generickd"
    md5_hashes   = "['2f0e9bb38da2cae16e6ce60b4720c51b','4320d5e83a69190512878a5cf42d42b1','fbea846039ef3fe8a2891963752f4f7d']"

  strings:
    $hex_string = { 64 c2 bd b9 ea f6 db 35 de 62 67 cc a1 9c 3d 7b 43 d9 16 5e 2f d9 b2 57 1d f1 37 2d 6a fa 92 f4 55 bc 31 b8 9e 70 47 9d 7e 78 21 f9 f3 ae e7 b0 23 f8 fc b7 9b 22 77 12 ef 75 a7 cd 5a 43 3a 7f }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}