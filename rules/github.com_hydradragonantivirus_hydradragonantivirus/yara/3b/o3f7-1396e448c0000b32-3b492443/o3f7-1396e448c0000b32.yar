rule o3f7_1396e448c0000b32 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=o3f7.1396e448c0000b32"
    cluster      = "o3f7.1396e448c0000b32"
    cluster_size = "323"
    filetype     = "text/html"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171123"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "script faceliker clicker"
    md5_hashes   = "['00e359eb715f1c1bf4204bc2ebe8afc8','012023b72d2a1f78363a9569029f92a4','0989b54e2101b2bd6d9a68afb79cbce2']"

  strings:
    $hex_string = { 53 c4 b0 4e c4 b0 5a 20 54 c3 9c 52 4b c4 b0 59 45 26 23 33 39 3b 44 45 20 32 2e 20 54 55 52 20 48 45 59 45 43 41 4e 49 3c 2f 61 3e 0a 3c 73 70 61 6e 20 64 69 72 3d 27 6c 74 72 27 3e 28 31 29 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}