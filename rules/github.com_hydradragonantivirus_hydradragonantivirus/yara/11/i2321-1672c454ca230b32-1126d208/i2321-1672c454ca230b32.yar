rule i2321_1672c454ca230b32 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=i2321.1672c454ca230b32"
    cluster      = "i2321.1672c454ca230b32"
    cluster_size = "12"
    filetype     = "application/gzip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171124"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "padodor backdoor symmi"
    md5_hashes   = "['0c28daffb42eec01bad601f22a121ea1','1d390d70b20f90497e523b5047d805fb','d4e9f1928a95489da50da97749dadc9b']"

  strings:
    $hex_string = { 59 c9 bc 6d a5 8c 3d 57 75 92 8d ef 57 33 4f 14 fe e4 54 a1 89 ec bb d8 b8 10 db 83 5d ac 3f 88 e5 d8 32 23 d7 9c e9 f8 b0 a4 53 b1 6a 29 2d ca 4e 28 79 17 be 1d 53 11 58 43 12 a8 9b d4 56 81 }

  condition:
    filesize > 1024 and filesize < 4096
    and $hex_string
}