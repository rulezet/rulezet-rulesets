rule o3f1_119b9bc9cc000b12 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=o3f1.119b9bc9cc000b12"
    cluster      = "o3f1.119b9bc9cc000b12"
    cluster_size = "14"
    filetype     = "application/zip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171123"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "androidos hiddad mobidash"
    md5_hashes   = "['1b039f9683a99313448ae942d31942fb','26d24c503d603880a84184f3b19cbca0','e1df286a55a311fbda8e16574a849a32']"

  strings:
    $hex_string = { 60 74 52 4e 53 00 0c 57 9a ca eb fa 9b 58 0d 22 99 f4 f5 24 07 86 f9 88 08 20 ce d0 80 2c e6 e7 2d e8 cd 84 21 d1 69 26 06 68 98 f8 6a 01 66 f7 0b f3 42 40 55 d2 c7 6b e9 28 fb 29 c6 6c 93 d3 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}