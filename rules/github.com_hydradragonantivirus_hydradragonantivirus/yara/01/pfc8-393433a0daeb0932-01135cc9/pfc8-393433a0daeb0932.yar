rule pfc8_393433a0daeb0932 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=pfc8.393433a0daeb0932"
    cluster         = "pfc8.393433a0daeb0932"
    cluster_size    = "80"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180909"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "fwefw highconfidence jiagu"
    md5_hashes      = "['74f13af94f9164e727539de2e4e3f83692f944b1','0f4a127ee348183ef31774c3ff5dde8d052abc64','9439a52c6a4794f5917f7086a72cb6baa02af264']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=pfc8.393433a0daeb0932"

  strings:
    $hex_string = { bb 1f 69 2b 6d 9f 6e 8d f4 cd 44 1b 82 72 a5 3b 36 0f f3 d7 fd 80 19 e5 5d 14 64 c1 a6 d5 d8 73 ea c6 31 06 7c c2 ce 35 78 ef 5e 26 a2 5f cc 15 37 1c e0 f8 57 24 67 34 de 51 54 ca 3e 75 2f 33 }

  condition:
    filesize > 4194304 and filesize < 16777216
    and $hex_string
}