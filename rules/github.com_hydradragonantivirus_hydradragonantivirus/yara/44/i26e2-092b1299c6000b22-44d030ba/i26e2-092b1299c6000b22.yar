rule i26e2_092b1299c6000b22 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=i26e2.092b1299c6000b22"
    cluster         = "i26e2.092b1299c6000b22"
    cluster_size    = "10"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "dorkbot winlnk jenxcus"
    md5_hashes      = "['2b13fc7e68dd6b76b5e31b78f1398848509d6993','387b328141db59538ea40dd314ef69dccb4a2025','2b02003b1f2c6e75bcc7daefe6a47a91f12b7463']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=i26e2.092b1299c6000b22"

  strings:
    $hex_string = { 1f 50 e0 4f d0 20 ea 3a 69 10 a2 d8 08 00 2b 30 30 9d 19 00 2f 43 3a 5c 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 52 00 31 00 00 00 00 00 00 00 00 00 10 00 77 69 6e 64 6f 77 73 }

  condition:
    filesize > 1024 and filesize < 4096
    and $hex_string
}