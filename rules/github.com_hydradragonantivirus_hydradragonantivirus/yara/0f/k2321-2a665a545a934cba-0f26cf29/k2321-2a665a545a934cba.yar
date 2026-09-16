rule k2321_2a665a545a934cba {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k2321.2a665a545a934cba"
    cluster      = "k2321.2a665a545a934cba"
    cluster_size = "4"
    filetype     = "PE32 executable (GUI) Intel 80386"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "tinba zusy flmp"
    md5_hashes   = "['14452531b78e81aac6feba1ffff8624f','22b1f5014e39d6f91f729e6b9fcc48b8','948e1856062a605534936afa624c5366']"

  strings:
    $hex_string = { c6 84 4b dd 78 b1 ea f4 3c 88 3a 16 a2 c2 63 d1 02 49 e6 48 e2 20 c5 40 7e 3f 00 ae 0a 68 f6 9b 99 e5 05 38 7d 4a 98 e8 08 a8 6f 42 b2 55 e9 c1 a7 26 03 7c 33 41 65 53 3b c0 be 4c aa 89 c9 a3 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}