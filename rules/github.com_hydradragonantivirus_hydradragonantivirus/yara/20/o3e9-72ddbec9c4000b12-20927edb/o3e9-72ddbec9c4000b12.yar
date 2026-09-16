rule o3e9_72ddbec9c4000b12 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=o3e9.72ddbec9c4000b12"
    cluster      = "o3e9.72ddbec9c4000b12"
    cluster_size = "10"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171123"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "virlock tdss nabucur"
    md5_hashes   = "['0a9f6bf789e752259f3660b4a902f27c','235b5494f1362d26a62df7bd4c24cfac','d8bc7bf6b628eb9e6886a3d124f504bf']"

  strings:
    $hex_string = { e6 e4 00 e3 e6 e4 00 e2 e5 e3 00 e2 e5 e4 00 e8 eb e9 00 ae b0 b1 00 6a 57 4a 00 60 34 1c 00 44 28 21 00 15 11 14 00 11 14 1c 00 47 49 4d 00 e7 e9 e7 00 ed f4 ee 00 ee f4 ee 00 ee f2 ee 00 e1 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}