rule o422_31b85ac348001132 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=o422.31b85ac348001132"
    cluster         = "o422.31b85ac348001132"
    cluster_size    = "910"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180909"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "razy kryptik adposhel"
    md5_hashes      = "['739115bcb91c62b11154cca4f28beb65d6cadff2','11b924d1e6a191e238be279b1596a32356a222c5','2cf7c098d72730cdb327dc410cdadf72f7110a17']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=o422.31b85ac348001132"

  strings:
    $hex_string = { 3d 98 0f ad 50 df 9e a9 f0 d4 e1 e2 a1 99 a9 58 f0 d4 e1 e2 64 8b cf a4 83 7b 49 ef f0 d4 e1 e2 d1 b0 ec c6 f0 d4 e1 e2 47 ca a6 36 c1 dd cc ae f0 d4 e1 e2 c3 bf 25 74 f0 d4 e1 e2 27 be e9 f9 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}