rule k2321_29359422ddb39932 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k2321.29359422ddb39932"
    cluster      = "k2321.29359422ddb39932"
    cluster_size = "42"
    filetype     = "application/gzip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "installm unwanted downware"
    md5_hashes   = "['050a7080e45d6f1ba6a1bc4b41825fb8','08b8b12d398061393a200828ce5f95d3','4fe35ee76f0fe0368813b7eae32d6557']"

  strings:
    $hex_string = { 47 06 04 0c 0b 99 1c e9 1b 39 83 d9 c4 b5 1e ee e7 e4 ef 1f 19 10 15 05 76 4a 6b 58 b8 af bf 3a 5f 14 03 ed cc c1 32 6e e1 fe b2 d0 00 17 df 30 7f 4a db 38 4c 13 c5 84 48 07 86 fb 63 c7 7e b4 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}