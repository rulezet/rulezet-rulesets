rule o26c0_59eb2802d0000132 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=o26c0.59eb2802d0000132"
    cluster         = "o26c0.59eb2802d0000132"
    cluster_size    = "182"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180909"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "deay malicious kryptik"
    md5_hashes      = "['76c3c0319e1e334318160267701e57827a440859','2d799e656982aed4c80d45506b8999777887cf21','672aa689c438533e35d1b428fc478ad43b633aa9']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=o26c0.59eb2802d0000132"

  strings:
    $hex_string = { 00 00 00 00 00 00 f0 3f cf 95 6b 86 a1 7c b3 bf 63 a9 ae a6 e2 7d d8 3f 00 00 00 e0 ed 2c 67 bc 00 00 00 00 00 00 f0 3f 79 12 fa 73 68 3a be bf 3b f6 06 38 5d 2b de 3f 00 00 00 20 89 0d 5e 3c }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}