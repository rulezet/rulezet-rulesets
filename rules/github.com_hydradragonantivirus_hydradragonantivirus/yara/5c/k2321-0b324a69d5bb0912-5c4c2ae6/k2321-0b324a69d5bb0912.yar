rule k2321_0b324a69d5bb0912 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k2321.0b324a69d5bb0912"
    cluster      = "k2321.0b324a69d5bb0912"
    cluster_size = "4"
    filetype     = "application/gzip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "ganelp autorun emailworm"
    md5_hashes   = "['5793019b3cf0c0b77d0ea167762c6cf8','9e571cc4a58b89efcc290753ae436a24','ef2a8ceb1f9f84ab63043944f95632b3']"

  strings:
    $hex_string = { 5a 6a 2d 7e 54 3c 26 75 2f d4 1f b9 53 09 66 a3 60 36 94 18 f2 f1 d8 8c c5 30 44 5e 76 55 3b a8 48 e4 a9 4c 80 bc 97 68 d2 21 6b 05 bd a6 31 cd e2 95 f7 63 95 f5 42 3f 1d 6d b5 92 72 da 80 41 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}