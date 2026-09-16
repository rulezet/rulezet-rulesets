rule o3e9_69349092d9ab0912 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=o3e9.69349092d9ab0912"
    cluster      = "o3e9.69349092d9ab0912"
    cluster_size = "171"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "graftor zusy backdoor"
    md5_hashes   = "['007e56bce47938c147b802d4604b7b9b','01b55863c70af7ffc66cf8405e144339','1a0da4b1637cf1d309bc095f45f53188']"

  strings:
    $hex_string = { c7 b1 97 e3 ab 3f d6 0d ed 23 24 6f 5e be 7a ba 61 18 d1 12 70 ad f6 63 fb 46 17 3e 01 8c ae f9 fe 7e 60 a6 76 4f b5 19 b6 1e f1 8b 04 db 16 e8 08 07 2f 56 34 4e a5 98 c9 f4 f3 62 7c a8 28 1b }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}