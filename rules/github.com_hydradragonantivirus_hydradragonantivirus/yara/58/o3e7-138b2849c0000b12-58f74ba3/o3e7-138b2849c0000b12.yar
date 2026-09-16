rule o3e7_138b2849c0000b12 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=o3e7.138b2849c0000b12"
    cluster      = "o3e7.138b2849c0000b12"
    cluster_size = "4"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171122"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "snojan malicious qjwmonkey"
    md5_hashes   = "['4cfe2ce6b53316a3910f0b47d2380b91','9bfddb14eb18e63f369e5851d3c2193d','f7ae0d0c08c2a686e184f212e4019b2e']"

  strings:
    $hex_string = { 3f 00 1c 31 c0 a8 27 4d 3a b0 0b e5 18 26 8d 05 48 60 28 f2 50 6f 33 49 4b a1 c3 25 f8 32 68 93 30 4c 46 d1 c9 de 38 76 80 d0 94 64 65 ff 8b 0d 4a 05 e6 c5 b9 a6 d4 be fd 0c 24 23 02 eb 82 9f }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}