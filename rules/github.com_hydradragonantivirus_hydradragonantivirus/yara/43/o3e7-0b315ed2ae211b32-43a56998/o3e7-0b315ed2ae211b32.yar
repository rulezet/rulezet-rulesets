rule o3e7_0b315ed2ae211b32 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=o3e7.0b315ed2ae211b32"
    cluster      = "o3e7.0b315ed2ae211b32"
    cluster_size = "3"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171123"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "installmonstr dlboost malicious"
    md5_hashes   = "['05d8866b82f5a6a346630ada0b94df0b','3467f99a51e7eb69a4f2a3e7166930ea','874755fc81a59339694623d1fdafdd61']"

  strings:
    $hex_string = { dc 61 64 18 53 07 bb 96 ab 0f d6 e8 b4 81 9e 19 eb 72 4e ae aa 9c 16 f9 c2 a2 dd 27 ed 3d 46 a9 26 a1 a7 57 51 89 28 fc 21 c3 c5 9a 36 e1 2a c6 da 9b 33 90 85 f3 54 a4 8a d3 29 88 e2 fd 5d 59 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}