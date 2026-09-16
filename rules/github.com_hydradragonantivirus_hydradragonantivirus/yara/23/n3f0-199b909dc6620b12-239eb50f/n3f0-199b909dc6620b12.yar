rule n3f0_199b909dc6620b12 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=n3f0.199b909dc6620b12"
    cluster      = "n3f0.199b909dc6620b12"
    cluster_size = "20"
    filetype     = "PE32 executable (GUI) Intel 80386 (stripped to external PDB)"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "amonetize adae genericr"
    md5_hashes   = "['09567ebf254d4a89dca15c5e6ea9b905','0e835b7cd62764152e0c3bc24fa4c344','be19cc877c74e3dbd535ba00c7973972']"

  strings:
    $hex_string = { 73 66 97 c9 a9 1e 7c c2 07 63 f8 16 12 11 ef 21 c1 3b 4e 62 04 74 6e cd 85 b6 c3 db 24 ba bd c4 8b 67 a0 ea 75 be 6a 99 38 3a 77 d0 bb d1 a5 d7 a6 b5 cc f5 eb dd 81 cf 57 08 e8 17 a2 af f3 e9 }

  condition:
    filesize > 262144 and filesize < 1048576
    and $hex_string
}