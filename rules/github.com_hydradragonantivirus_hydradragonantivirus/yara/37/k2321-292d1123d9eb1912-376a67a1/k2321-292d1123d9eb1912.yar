rule k2321_292d1123d9eb1912 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k2321.292d1123d9eb1912"
    cluster      = "k2321.292d1123d9eb1912"
    cluster_size = "4"
    filetype     = "application/gzip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "vobfus symmi vbkrypt"
    md5_hashes   = "['53b838cec87cd047602b6e03a32d9bf2','59a12476fb25b9dd13966c66d4eb69b0','fca437ecd8d108e3ec9880c7435a7fdd']"

  strings:
    $hex_string = { 40 6c 66 1d 4c 38 03 55 31 f8 d4 27 de 7a a6 ef fa f6 b3 81 d8 d3 eb c0 c3 f2 ce 15 98 3f fc 7d fb 45 08 85 50 7c 8c bd 09 3e 84 93 88 56 23 f5 dd 77 f8 78 e7 0e 4e 39 e4 6d 89 ae a5 13 23 2a }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}