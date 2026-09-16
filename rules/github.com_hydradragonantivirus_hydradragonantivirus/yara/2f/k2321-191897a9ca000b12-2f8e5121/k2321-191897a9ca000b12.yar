rule k2321_191897a9ca000b12 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k2321.191897a9ca000b12"
    cluster      = "k2321.191897a9ca000b12"
    cluster_size = "5"
    filetype     = "PE32 executable (GUI) Intel 80386"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "nimnul vjadtre small"
    md5_hashes   = "['7bf52b8cc80679bebb964948e7d2fe48','7e979d3d6343f68a5b6fc74e4c7021a6','f561eda92ea4aaa5315ae6658bd5bd44']"

  strings:
    $hex_string = { 9c 32 2e c8 15 0f d9 1a eb df da 1c 52 70 a9 72 68 0a 3b 60 5f 91 0a b6 9e 8d 6a 6d 0e 46 26 6c d0 49 29 70 59 3f 2b c5 e3 67 84 64 02 b0 40 cf 2f 7d 16 00 db b5 e4 e1 0c 84 0d 47 4b 73 b4 10 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}