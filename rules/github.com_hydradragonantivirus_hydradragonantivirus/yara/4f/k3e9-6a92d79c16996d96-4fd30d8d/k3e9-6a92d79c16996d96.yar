rule k3e9_6a92d79c16996d96 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e9.6a92d79c16996d96"
    cluster      = "k3e9.6a92d79c16996d96"
    cluster_size = "320"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "outbrowse bundler nsis"
    md5_hashes   = "['010caba65aa378aef43ccdcb4597971d','01ef7ddc4149015587870f796744ac20','155dcaf0b44fab88fd39ad69715f5bd5']"

  strings:
    $hex_string = { 61 55 00 de 1e f2 5f a1 5e fb 07 08 47 bf 83 a0 09 10 d4 d0 b4 84 33 8b 4b f9 cc ee 27 f3 fe 52 3c e3 3f 64 b5 fe 7b 56 8f ff 90 d5 f6 ef 59 cf 74 7f 1b c3 65 fc 80 51 92 cc 4a b7 97 50 0e 8c }

  condition:
    filesize > 262144 and filesize < 1048576
    and $hex_string
}