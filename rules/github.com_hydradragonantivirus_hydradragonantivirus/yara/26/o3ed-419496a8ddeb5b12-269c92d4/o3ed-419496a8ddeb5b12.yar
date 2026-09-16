rule o3ed_419496a8ddeb5b12 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=o3ed.419496a8ddeb5b12"
    cluster      = "o3ed.419496a8ddeb5b12"
    cluster_size = "70"
    filetype     = "PE32 executable (DLL) (GUI) Intel 80386"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "ramnit nimnul patched"
    md5_hashes   = "['003a0be547d49e8db969017a6d47854c','01e312c1457718f54567c3c726f45fda','0fa149b801286157853e803f2807c10f']"

  strings:
    $hex_string = { 8b 38 7a 39 9f 3a a5 3a c0 3a 7f 3b 9e 3c a6 3c b9 3c 69 3d 6f 3d be 3e c7 3e cd 3e 00 f0 10 00 6c 00 00 00 95 31 d0 31 03 32 73 32 87 33 dd 33 a7 34 ff 34 7c 35 d9 36 6d 37 96 37 2e 38 4a 39 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}