rule n3f0_0e930d4bdabb1912 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=n3f0.0e930d4bdabb1912"
    cluster      = "n3f0.0e930d4bdabb1912"
    cluster_size = "6"
    filetype     = "PE32 executable (GUI) Intel 80386 (stripped to external PDB)"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "mira symmi malicious"
    md5_hashes   = "['ab9d8001bbe0e17becd3b27579e1dfd1','c48d73a6e0a3d8fccb0a3d705334dda0','deee0095f118d1f2f8573dc03d3e8c6a']"

  strings:
    $hex_string = { 22 f3 07 09 12 64 30 63 cb 9a 20 28 b8 53 f1 7d f0 0f 87 ae e8 68 2c c0 b1 00 81 5b 59 26 1e 1a 90 56 c8 b9 c1 71 f2 43 35 0e 4d 69 e9 f5 9e 6a 32 fd d2 13 4a 9f 0b d1 41 8c f4 0a 7c 7b a1 80 }

  condition:
    filesize > 262144 and filesize < 1048576
    and $hex_string
}