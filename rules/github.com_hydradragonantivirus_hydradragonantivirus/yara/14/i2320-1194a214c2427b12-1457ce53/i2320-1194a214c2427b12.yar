rule i2320_1194a214c2427b12 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=i2320.1194a214c2427b12"
    cluster         = "i2320.1194a214c2427b12"
    cluster_size    = "22"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "exploit msoffice expl"
    md5_hashes      = "['9937ebd2d4a02b9ee96b88d2e28fd8002cd9072c','49f7483906e7a4a09516eb815ff03293c9b41aa2','8869b1b365287f0299b3a03c152536341d1f227d']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=i2320.1194a214c2427b12"

  strings:
    $hex_string = { 92 2a a8 63 91 2b 45 b5 34 e3 10 98 24 61 91 e8 5f da e1 4d ab 06 1e 0d ea 31 db b0 bf 11 41 76 b5 ce 14 e5 c3 56 bc f0 9d ef b2 8c 78 24 cb 0f 39 dc 5d 5c 59 77 93 90 54 10 96 cd d9 bb cf 4f }

  condition:
    filesize > 1024 and filesize < 4096
    and $hex_string
}