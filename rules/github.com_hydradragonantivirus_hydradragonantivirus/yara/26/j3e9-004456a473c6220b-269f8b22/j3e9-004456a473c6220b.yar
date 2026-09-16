rule j3e9_004456a473c6220b {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=j3e9.004456a473c6220b"
    cluster      = "j3e9.004456a473c6220b"
    cluster_size = "4"
    filetype     = "PE32 executable (GUI) Intel 80386"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171117"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "small madang madangel"
    md5_hashes   = "['515b571234f987d8230c4521800896d0','a1aff4b78e8d92ce1aa9ec153accd94f','f2aaae13115e63868ae6042a739c7ad4']"

  strings:
    $hex_string = { 66 81 3e 4d 5a 78 03 79 01 eb 75 ee 0f b7 7e 3c 03 fe 8b 6f 78 03 ee 8b 5d 20 03 de 33 c0 8b d6 83 c3 04 40 8b 3b 03 fa e8 0f 00 00 00 47 65 74 50 72 6f 63 41 64 64 72 65 73 73 00 5e 33 c9 b1 }

  condition:
    filesize > 4096 and filesize < 16384
    and $hex_string
}