rule k3e9_6ab2c252d88ad111 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e9.6ab2c252d88ad111"
    cluster      = "k3e9.6ab2c252d88ad111"
    cluster_size = "766"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171118"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "jykg heuristic hfsadware"
    md5_hashes   = "['00554d3d6aeac8cf56a3a5614f376642','00a89afdd7f02ab43109f4508f71b6b2','07506e0e1b964327b5027bef92ddfa8d']"

  strings:
    $hex_string = { d6 13 35 e8 80 9a 29 f3 2e f7 cc 3b 9c cd 1d e7 d3 fc 2d 5d aa 9b 01 63 2d 7b 62 0f f2 7d 9d ef 62 7f ec e1 a6 0b 40 52 75 b0 31 32 8c d4 54 39 26 b8 49 3d 4b a3 eb 6c 58 82 96 d1 a7 d0 ce bb }

  condition:
    filesize > 65536 and filesize < 262144
    and $hex_string
}