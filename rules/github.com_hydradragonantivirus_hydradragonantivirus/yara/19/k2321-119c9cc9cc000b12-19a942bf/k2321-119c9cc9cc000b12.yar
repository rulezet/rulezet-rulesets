rule k2321_119c9cc9cc000b12 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k2321.119c9cc9cc000b12"
    cluster      = "k2321.119c9cc9cc000b12"
    cluster_size = "184"
    filetype     = "application/gzip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "vilsel aems heuristic"
    md5_hashes   = "['00b0462b5926e668735c2f71bf461d1d','00bf68a4edcfe93dafc63d134d7d13b6','174b21c1b0864916273c917c04f2a33b']"

  strings:
    $hex_string = { 53 ab 41 30 4b 0e bb 5e 2b 76 28 68 c4 4d 7a 1b bd 3c 22 f3 8c 5a be af f1 9e b9 8b 49 93 88 52 f4 0a be b0 4c 45 ea 86 59 c1 04 9b 44 6a 1a a6 be e0 94 48 51 cc 79 b6 dc 4a 9d a3 54 85 95 3a }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}