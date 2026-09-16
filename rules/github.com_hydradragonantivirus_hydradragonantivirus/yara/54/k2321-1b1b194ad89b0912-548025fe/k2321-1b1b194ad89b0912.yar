rule k2321_1b1b194ad89b0912 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k2321.1b1b194ad89b0912"
    cluster      = "k2321.1b1b194ad89b0912"
    cluster_size = "45"
    filetype     = "application/gzip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "vbkrypt symmi gamarue"
    md5_hashes   = "['068140dde7ceca58e8c2fe2fb07b4836','0f20516be5ac518de1db5db48708cf81','66a51e91a388a6db7ead98e88738f201']"

  strings:
    $hex_string = { 34 c6 26 4b 53 f2 0e 7d 36 a0 b4 b6 62 c1 b2 e9 25 44 1e 0f 2c 69 b0 ee 28 c4 3c 11 b5 5c 29 aa 50 3b 70 66 9b 5d 6a a1 35 21 85 9e b3 d0 8f b2 2d b1 93 f5 08 37 09 18 77 07 c5 8a ef 1a 0c 3d }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}