rule j2321_1a3a7a5cd2ab1912 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=j2321.1a3a7a5cd2ab1912"
    cluster      = "j2321.1a3a7a5cd2ab1912"
    cluster_size = "5"
    filetype     = "application/gzip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "spyeyes upatre generickd"
    md5_hashes   = "['097f2e9e2fcf89e3b9ca5d2a70e83f5d','217649328458f65827c4514d26afd272','ca640e46ed15bbd484f3ec5ba73aee1d']"

  strings:
    $hex_string = { a8 24 f0 17 f4 8f 90 4b 84 96 5e 7f ef 2b 42 37 d4 39 12 9d 75 15 72 f7 62 cc 84 18 9f b6 a6 3a ec 4d cf 40 c8 a0 85 5b 4c e7 7a 80 3b 63 88 c8 28 a7 b3 f2 e0 34 79 68 e5 97 f6 8b 21 5d 72 43 }

  condition:
    filesize > 4096 and filesize < 16384
    and $hex_string
}