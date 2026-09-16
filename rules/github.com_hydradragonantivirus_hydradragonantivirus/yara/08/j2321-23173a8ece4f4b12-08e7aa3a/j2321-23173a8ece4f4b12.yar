rule j2321_23173a8ece4f4b12 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=j2321.23173a8ece4f4b12"
    cluster      = "j2321.23173a8ece4f4b12"
    cluster_size = "4"
    filetype     = "application/gzip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "upatre trojandownloader generickd"
    md5_hashes   = "['56ff9a8e3c454c4f9d201072c9fbe377','6a445fe5f65ccc9301bd66a549a4d29d','b4eea83d7156f742ca0c64a9e91d908a']"

  strings:
    $hex_string = { 50 71 81 f3 eb 7b 29 3b 83 dc 27 49 bd 95 37 c9 30 e5 21 3c 65 e1 07 5b 32 4d 3d c0 b1 bc 46 53 33 57 11 e6 de 0e a5 d5 e4 39 08 3e 1b 0f d1 90 2a c1 68 a4 2b 9b e1 ee 09 4e 0e ed 74 a2 f1 0d }

  condition:
    filesize > 4096 and filesize < 16384
    and $hex_string
}