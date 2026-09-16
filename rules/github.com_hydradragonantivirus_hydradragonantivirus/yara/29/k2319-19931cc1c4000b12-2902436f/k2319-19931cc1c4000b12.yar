rule k2319_19931cc1c4000b12 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k2319.19931cc1c4000b12"
    cluster      = "k2319.19931cc1c4000b12"
    cluster_size = "37"
    filetype     = "text/html"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "refresh html redirme"
    md5_hashes   = "['000acbb8d834873020aaa9819e190b04','00b58d782c210fb9c133119ca52c3677','434485244e1b68989611a2801454a5d2']"

  strings:
    $hex_string = "{};$.tmpl=function e(a,c){var d=!/\\W/.test(a)?b[a]=b[a]||e(docum"

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}