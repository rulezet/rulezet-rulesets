rule n3ed_1111a08ada226916 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=n3ed.1111a08ada226916"
    cluster      = "n3ed.1111a08ada226916"
    cluster_size = "66"
    filetype     = "PE32 executable (DLL) (GUI) Intel 80386"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "symmi delf atraps"
    md5_hashes   = "['00d93e4f622f253a4871c55d17fd8e7e','0c59bb884eca203fac8ff21afbb9bb1e','982df60dc6b996a5385c77333be87ec2']"

  strings:
    $hex_string = { ec b3 c3 9e d1 7c 53 48 f6 46 ba df f8 40 ab d0 22 fa 6c a6 09 7e 34 3e 01 d7 cd 91 56 90 26 2d 5e 5b dc 6f 8f 55 e1 24 d9 1e e3 ad 7f 8e d3 88 bc 83 84 14 e7 d6 a9 42 00 fd 71 b1 72 ce a8 64 }

  condition:
    filesize > 262144 and filesize < 1048576
    and $hex_string
}