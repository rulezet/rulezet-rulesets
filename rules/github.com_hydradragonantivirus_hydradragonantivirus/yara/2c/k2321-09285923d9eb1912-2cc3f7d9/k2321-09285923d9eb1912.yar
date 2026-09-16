rule k2321_09285923d9eb1912 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k2321.09285923d9eb1912"
    cluster      = "k2321.09285923d9eb1912"
    cluster_size = "4"
    filetype     = "application/gzip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "vobfus conjar autorun"
    md5_hashes   = "['1ffa28131cb4bc684c4c01de2057142b','401c48d1ef3338ccaf282312f82347e2','9a6409004a3facf96e72e45ab3d3a16c']"

  strings:
    $hex_string = { d4 7f 29 6b 4b eb bf b1 09 5c 47 35 46 ac d6 ba c7 0c 3d 0a 39 38 2a aa 3c bc 14 16 01 34 92 9a 2f e7 96 ab 54 43 d1 ad 9c ce 59 f7 10 c2 69 dc c9 f6 de a6 93 ae 66 dd 11 21 cf f9 b3 b6 06 99 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}