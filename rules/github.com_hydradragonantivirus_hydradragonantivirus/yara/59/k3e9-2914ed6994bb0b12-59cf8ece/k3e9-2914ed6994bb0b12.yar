rule k3e9_2914ed6994bb0b12 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e9.2914ed6994bb0b12"
    cluster      = "k3e9.2914ed6994bb0b12"
    cluster_size = "5"
    filetype     = "PE32 executable (GUI) Intel 80386"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171118"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "zusy emotet tinba"
    md5_hashes   = "['017dbf3babf2e1d767d1d54c09d3858a','55a9d992db9fdfe401d6b9935d278a20','f8b3d9ce22767c16e8f60585249966aa']"

  strings:
    $hex_string = { cc 77 36 31 8d 8c aa 4d dc e8 b1 95 f4 79 ba af e5 42 ce 06 d2 28 5e 2e 03 ee ae 48 e0 fb 7a 86 7e f3 5d 85 09 ef 1d 49 2f 2a e1 a6 47 5c da 74 c5 3d e3 d6 34 13 7a cf a4 35 7d b4 eb bd 0e ad }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}