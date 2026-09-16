rule n3f1_693186c2dd12e113 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=n3f1.693186c2dd12e113"
    cluster      = "n3f1.693186c2dd12e113"
    cluster_size = "5"
    filetype     = "application/zip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171122"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "flystudio wpepro hacktool"
    md5_hashes   = "['080ed46d827aae43655930ad19722120','311fedad7ac797efbc95e69493f45c58','ec0bec43e6dabae0deab0d5634fba87c']"

  strings:
    $hex_string = { 4c 93 05 34 ee 76 7c a2 71 39 a1 6b d0 20 fb 27 a3 81 1d e9 31 9c 95 f0 d6 2a a8 eb c8 23 86 c9 97 2e da fc de c6 9d 88 ab 59 80 1e 33 5d 1f 6c 11 19 4e 49 55 e8 36 53 e6 66 d7 94 b6 35 3a fa }

  condition:
    filesize > 262144 and filesize < 1048576
    and $hex_string
}