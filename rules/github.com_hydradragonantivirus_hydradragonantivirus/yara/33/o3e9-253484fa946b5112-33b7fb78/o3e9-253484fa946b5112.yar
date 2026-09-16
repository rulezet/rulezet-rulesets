rule o3e9_253484fa946b5112 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=o3e9.253484fa946b5112"
    cluster      = "o3e9.253484fa946b5112"
    cluster_size = "4"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "cosmu mikey malicious"
    md5_hashes   = "['06e5cd20d733696e2d400220aab1b21c','b827286113d68eb2351b7553caaef16b','eab02e0b1960b6b18f2626eae2c38342']"

  strings:
    $hex_string = { 7f d7 88 09 87 10 db 76 8f ad 67 86 c5 68 3b ec bb 99 77 50 32 27 36 01 6f 05 3d 07 f2 9d 1e c8 3e b0 b5 30 79 25 72 f9 cd 29 7e cf e7 f1 82 2f 7a 31 46 c9 9b 8c 7d e9 54 21 06 a5 69 ac 49 cb }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}