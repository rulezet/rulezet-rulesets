rule k3e9_2b14e9c534264cb2 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e9.2b14e9c534264cb2"
    cluster      = "k3e9.2b14e9c534264cb2"
    cluster_size = "5"
    filetype     = "PE32 executable (GUI) Intel 80386"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "tinba crypt vbkrypt"
    md5_hashes   = "['4e8949c6452bac37294c7488890c31e5','56af2551d8ccf26f4345e71ef0865ec3','b83820ed1589651a0fefefffe9cec5df']"

  strings:
    $hex_string = { aa 18 20 02 06 98 61 fa 51 63 a7 4c 6b cc b5 11 29 c7 05 ba f6 d0 d2 da 76 1c c3 74 26 8b de d4 5c ad 8d b4 c5 00 d3 9b e6 71 2d 96 f7 f5 f9 52 34 ee e6 10 c8 22 4a 1e 0e d9 80 92 b3 21 1b 0a }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}