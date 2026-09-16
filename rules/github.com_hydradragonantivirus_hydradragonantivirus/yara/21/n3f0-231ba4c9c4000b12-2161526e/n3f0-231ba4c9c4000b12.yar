rule n3f0_231ba4c9c4000b12 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=n3f0.231ba4c9c4000b12"
    cluster      = "n3f0.231ba4c9c4000b12"
    cluster_size = "7"
    filetype     = "PE32 executable (GUI) Intel 80386 (stripped to external PDB)"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "mira bqcb malicious"
    md5_hashes   = "['ae13f4bbe97f4f74bbba3f52972f2089','b3151aa1786244393bb463a3d1693cd8','e222e5437be51c88237e4ffa0d229893']"

  strings:
    $hex_string = { d0 c1 e0 08 09 c3 66 89 19 83 e9 02 4e 0f b6 de 79 ea 0f b7 45 00 83 c7 08 f6 c4 ff 74 ce 66 85 c0 78 4a 8b 5c 24 1c 8d 73 10 89 f6 89 f1 31 c0 bb 06 00 00 00 eb 1c 90 8d 74 26 00 01 d2 a8 02 }

  condition:
    filesize > 262144 and filesize < 1048576
    and $hex_string
}