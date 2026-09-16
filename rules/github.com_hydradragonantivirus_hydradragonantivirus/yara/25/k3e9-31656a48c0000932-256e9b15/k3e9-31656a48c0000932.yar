rule k3e9_31656a48c0000932 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e9.31656a48c0000932"
    cluster      = "k3e9.31656a48c0000932"
    cluster_size = "438"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171111"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "small generickd trojandownloader"
    md5_hashes   = "['00a1f15bdc5ceeb22811ea2d9c2f58fe','024eb98e564f4040c6349ee22c01bb98','105f8294aa50674c031c36f1c8dc2c29']"

  strings:
    $hex_string = { 43 a7 4e 25 f8 ab 64 8e 04 0c 01 03 d8 b4 2b fa ad f4 c0 0e 0c 01 7c 35 74 26 19 1d 8b b6 0a 0c 01 cd 4d 4a 3e 5e 2f 39 42 00 0c 01 52 2a 28 40 44 1e 37 63 06 0c 01 15 db 83 fc e6 b2 d6 14 07 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}