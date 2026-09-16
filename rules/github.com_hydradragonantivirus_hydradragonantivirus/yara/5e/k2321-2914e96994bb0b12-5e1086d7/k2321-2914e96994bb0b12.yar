rule k2321_2914e96994bb0b12 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k2321.2914e96994bb0b12"
    cluster      = "k2321.2914e96994bb0b12"
    cluster_size = "5"
    filetype     = "application/gzip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = ""
    md5_hashes   = "['0444f4967b663b2aa7fe08515f5bdf73','64c8c824b221c67f7667b927ac6da995','e6f65f57ea0d7ccf101e1d3a95f11b32']"

  strings:
    $hex_string = { 49 6b 66 4a aa 67 88 2b 73 45 95 d3 84 75 33 f8 f5 b9 dc b3 53 d8 5f 0f f7 dd d6 87 31 2d 56 0c d3 b4 fe 3a a9 54 02 63 f9 dc 76 f0 10 70 59 42 3e 57 2a 93 ea fc fd 7b 86 06 cc 48 90 be d4 9f }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}