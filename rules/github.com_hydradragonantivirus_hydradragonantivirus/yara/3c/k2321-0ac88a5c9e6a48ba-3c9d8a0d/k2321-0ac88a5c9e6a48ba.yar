rule k2321_0ac88a5c9e6a48ba {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k2321.0ac88a5c9e6a48ba"
    cluster      = "k2321.0ac88a5c9e6a48ba"
    cluster_size = "14"
    filetype     = "application/gzip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "tinba zusy backdoor"
    md5_hashes   = "['0467dc9a3a646f1460c6487719855797','07bb34a83c96f10e8df8f9e519334048','fbc744793d0ba0d36a4f27609693e045']"

  strings:
    $hex_string = { 6b 86 79 31 ab bd 59 24 e0 bb 28 4f 09 1f b6 74 33 c6 29 7c 58 2e 00 a1 19 41 40 65 a0 44 5b ac d3 0d 5e 6d ec a6 78 af 6c 1b 7d 21 f9 f5 94 fe a3 2a c7 0e ed 89 03 a9 ad 27 71 62 73 8e a8 c9 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}