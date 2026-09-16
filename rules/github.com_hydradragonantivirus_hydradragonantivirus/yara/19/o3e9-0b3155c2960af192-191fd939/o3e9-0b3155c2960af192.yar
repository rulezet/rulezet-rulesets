rule o3e9_0b3155c2960af192 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=o3e9.0b3155c2960af192"
    cluster      = "o3e9.0b3155c2960af192"
    cluster_size = "1049"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171111"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "installmonster bundler installmonstr"
    md5_hashes   = "['0005b49c6f80abf59067adce90de2dcc','00beeaa53f8fb3293016a403af187f5f','039f115c5669d8f07655da14f4521562']"

  strings:
    $hex_string = { 87 7f c4 63 b3 a8 1d 5c f0 7d af fd cb c9 ef f2 48 01 40 9a cc ca f9 e5 12 28 3c 51 c3 ea eb 8c db 62 7a da a7 98 61 4e 70 1c 75 e6 18 47 6c 4b 36 2c 07 69 e4 2a 8b c1 57 7c f3 a5 08 92 a3 dd }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}