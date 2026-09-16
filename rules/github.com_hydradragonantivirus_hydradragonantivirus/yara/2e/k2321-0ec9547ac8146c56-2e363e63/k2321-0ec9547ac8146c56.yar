rule k2321_0ec9547ac8146c56 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k2321.0ec9547ac8146c56"
    cluster      = "k2321.0ec9547ac8146c56"
    cluster_size = "4"
    filetype     = "application/gzip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "yunsip zusy backdoor"
    md5_hashes   = "['6becbdc0b1271522e535a562f7c48368','970db04f2bdd09aed73692bccec08f13','f9e3f92f2b12aea3db6caa888e949edf']"

  strings:
    $hex_string = { 26 be f3 6c 01 66 0f 3c 0b c0 e1 e6 bc ea 8e fd 4a f6 23 e9 9a a9 b1 75 bb 8c 6e 4b b6 ae a1 fe 69 d3 8f cc 2d 88 99 36 1b 7b 8d 54 1a e7 6f cd c1 2c 81 d7 5a da 9f 33 d8 64 6d 62 42 0a 5b a7 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}