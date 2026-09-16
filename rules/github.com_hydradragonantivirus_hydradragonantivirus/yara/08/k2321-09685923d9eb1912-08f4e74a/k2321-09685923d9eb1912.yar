rule k2321_09685923d9eb1912 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k2321.09685923d9eb1912"
    cluster      = "k2321.09685923d9eb1912"
    cluster_size = "8"
    filetype     = "application/gzip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "vobfus conjar autorun"
    md5_hashes   = "['092ad8f8c48c6760fc91d66564f59378','15c2bdd346cc4368e3a804a1004373d0','bd4584d1551d6628b0bdd411f40c55da']"

  strings:
    $hex_string = { 3e cf f5 e6 61 cc d7 ab e9 33 f4 d0 70 64 8d 88 d6 19 46 a7 fd dd c7 d9 7f 47 68 fa f8 42 48 32 7e af 53 8e ed 95 11 df e1 dc 9d 9c c3 39 ea 2b 5b 9f c7 6d ce 27 8f 23 8a 86 8b 7a c0 e2 98 1e }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}