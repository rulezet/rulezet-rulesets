rule o3ed_499a91e9ca000b12 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=o3ed.499a91e9ca000b12"
    cluster      = "o3ed.499a91e9ca000b12"
    cluster_size = "12"
    filetype     = "PE32 executable (DLL) (GUI) Intel 80386"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "ramnit patched cosmu"
    md5_hashes   = "['1953e421714e9ef8151b4c5703ea8769','24bd16f97bd1b6906cf29fb02661cb47','f452e9dcef9f5d59a73ad2356af6c272']"

  strings:
    $hex_string = { 25 44 e9 a3 cc ef d2 a6 58 2e 96 ba 00 70 07 9e 7a 5e 6d bf 5f ec bd bb 9b 63 de 03 10 b5 8f 75 43 fb 84 1d f1 8a 13 72 7b d7 a2 60 39 3a c6 c1 ff 99 01 34 1c 35 05 d4 c9 69 ca 85 1a 83 3f 6b }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}