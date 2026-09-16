rule o3e9_409a3ec9c4000b32 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=o3e9.409a3ec9c4000b32"
    cluster      = "o3e9.409a3ec9c4000b32"
    cluster_size = "37"
    filetype     = "PE32 executable (GUI) Intel 80386"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171123"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "virlock tdss nabucur"
    md5_hashes   = "['1fc94f5d35635458664a5d67284e9bd4','2bf402d30c9cc0614d1cef75ea6197dd','c5e1f9d0e1a1a0c086d3ca2f4cd22a45']"

  strings:
    $hex_string = { 01 00 01 00 20 20 00 00 02 00 20 00 a8 10 00 00 01 00 50 41 44 44 49 4e 47 58 58 50 41 44 44 49 4e 47 50 41 44 44 49 4e 47 58 58 50 41 44 44 49 4e 47 50 41 44 44 49 4e 47 58 58 50 41 44 44 49 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}