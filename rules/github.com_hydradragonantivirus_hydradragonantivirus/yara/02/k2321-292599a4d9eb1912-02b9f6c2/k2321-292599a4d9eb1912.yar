rule k2321_292599a4d9eb1912 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k2321.292599a4d9eb1912"
    cluster      = "k2321.292599a4d9eb1912"
    cluster_size = "4"
    filetype     = "PE32 executable (GUI) Intel 80386"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "vobfus symmi vbkrypt"
    md5_hashes   = "['0ede5eca4f427d0dd89fef9fdef408d3','10650ca1640e43f9a82a9a1a5f77d9d1','29e3c31acb9b61d6b48e9615e048f0f4']"

  strings:
    $hex_string = { b1 0d c6 13 f2 a6 d4 84 bc 29 33 58 00 0b 3b 38 69 5f 9b c4 b9 9d 78 63 57 20 96 c5 49 fd 9c 89 cf 70 b7 52 d3 62 96 71 0c 40 88 d0 24 35 b0 92 3d 94 d8 af 04 c3 21 6f f8 8e 7c f9 50 22 54 15 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}