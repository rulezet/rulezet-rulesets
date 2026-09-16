rule k2321_0925b962d9eb1912 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k2321.0925b962d9eb1912"
    cluster      = "k2321.0925b962d9eb1912"
    cluster_size = "6"
    filetype     = "application/gzip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171121"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "vobfus symmi autorun"
    md5_hashes   = "['2488595f0e1416644d1f84d542966409','35bdf17ce68640ddfea7b1d4a621a1bc','fb1d02c9aee3678d48c99f569190d991']"

  strings:
    $hex_string = { aa 4d 3e 46 5a 18 17 4a 67 e6 a5 a6 d6 a2 3d 29 e6 be 1f 38 02 a4 60 53 0f f1 69 3c fa 14 bb 1c c3 4b 83 a4 98 ba f2 10 6d c8 e2 7c 1d 2b da 90 8d 85 0b f6 94 99 f9 6b b1 8f 16 27 54 95 0c 9a }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}