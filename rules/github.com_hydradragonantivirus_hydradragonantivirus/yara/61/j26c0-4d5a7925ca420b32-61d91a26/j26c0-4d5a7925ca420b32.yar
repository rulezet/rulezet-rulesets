rule j26c0_4d5a7925ca420b32 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=j26c0.4d5a7925ca420b32"
    cluster         = "j26c0.4d5a7925ca420b32"
    cluster_size    = "4"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "virtob malicious virut"
    md5_hashes      = "['9296c872be2d1925b72c78af45369bfbda8fcd9c','f977365615215afb19f4fa1cddcb0418948656f0','70529b2f59cd18cee5e4e1e8d2a9c5d42a3f1757']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=j26c0.4d5a7925ca420b32"

  strings:
    $hex_string = { 43 6f 72 65 2d 53 79 73 49 6e 66 6f 2d 4c 31 2d 31 2d 30 2e 64 6c 6c 00 00 13 06 e3 77 6e f2 e2 77 a0 ef e2 77 00 00 00 00 9d 6b ce 0d 40 67 ce 0d 00 00 00 00 e1 e1 f5 6f 27 3e f7 6f cf 61 fa }

  condition:
    filesize > 4096 and filesize < 16384
    and $hex_string
}