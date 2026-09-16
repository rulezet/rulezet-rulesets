rule o3e9_13892949c0000916 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=o3e9.13892949c0000916"
    cluster      = "o3e9.13892949c0000916"
    cluster_size = "1104"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171111"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "downloadsponsor ocna riskware"
    md5_hashes   = "['00f13cdec352b265282a8ddd5b9fd12f','0125cc66658501703ecea95a6e389c39','0657107786c1189087d6e748fce1e7da']"

  strings:
    $hex_string = { 6b a9 03 af e4 63 b6 fa d5 23 27 f4 60 17 9e c8 99 46 38 20 5f 6e d3 2f 75 3e e6 8c a7 f3 ce 1d 39 5e 8d b6 dd ed 5a b5 fc e5 d9 2b bd a4 c3 0c 99 18 ef a3 cc 3b 1f 7a 52 56 74 ea 54 ff c7 95 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}