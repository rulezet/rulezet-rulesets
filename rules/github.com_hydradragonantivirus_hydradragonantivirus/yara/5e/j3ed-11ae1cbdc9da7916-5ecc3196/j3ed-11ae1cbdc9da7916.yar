rule j3ed_11ae1cbdc9da7916 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=j3ed.11ae1cbdc9da7916"
    cluster      = "j3ed.11ae1cbdc9da7916"
    cluster_size = "97"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "proxy malicious trojanproxy"
    md5_hashes   = "['0144b2c8e06be6499873bfc02e28b314','04ca173bf37c20d34956dfb7a132c2d9','2fd437d0ca2c57092abad22704dbe428']"

  strings:
    $hex_string = { d1 52 ba 64 43 b2 5c b8 ce 51 00 10 40 89 10 b2 66 86 d6 88 70 04 b2 61 86 d6 88 70 08 51 b9 2a 19 75 17 87 d1 29 10 59 8b 15 38 11 00 10 28 50 06 5a eb 05 eb 62 ff d0 c3 53 56 57 5b bf a0 5d }

  condition:
    filesize > 4096 and filesize < 16384
    and $hex_string
}