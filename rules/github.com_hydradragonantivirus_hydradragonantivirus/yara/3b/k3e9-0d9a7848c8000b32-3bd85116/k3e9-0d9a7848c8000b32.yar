rule k3e9_0d9a7848c8000b32 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e9.0d9a7848c8000b32"
    cluster      = "k3e9.0d9a7848c8000b32"
    cluster_size = "1045"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171123"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "dropped lanman laqma"
    md5_hashes   = "['0081b92d70259b007a0e13574c284c7d','00bd6957a3ff9fc7f06cc665fde212f2','08b647f1126efdb33173edb13f01f9fe']"

  strings:
    $hex_string = { f0 74 15 57 8b c2 6a 04 99 5f f7 ff 5f 85 d2 74 07 6a 04 58 2b c2 03 c8 f6 44 24 0c 02 75 04 8d 4c 71 02 8b c1 5e c3 55 8b ec 83 ec 18 53 33 db 39 5d 08 56 57 0f 84 47 01 00 00 8b 7d 10 3b fb }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}