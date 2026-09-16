rule o26c0_5b1ad0ce9cbb1912 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=o26c0.5b1ad0ce9cbb1912"
    cluster         = "o26c0.5b1ad0ce9cbb1912"
    cluster_size    = "8"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180909"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "graftor heuristic kryptik"
    md5_hashes      = "['8169764dc8b30e68af62b371a8cd6e385d7bec18','845dc57cf71d0163eb53272c26a9a2a78097dc71','92337bd0a43bd7b9549a015d8fdf25214d8df8fb']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=o26c0.5b1ad0ce9cbb1912"

  strings:
    $hex_string = { bf 27 fe f4 57 26 a3 4f eb 80 08 06 89 64 b4 6f 1e 55 ae 62 68 b0 2b fa ab 00 41 ce 1d ca ad b5 a5 b8 11 4b ef 88 d4 69 b6 a6 3f e0 21 60 51 00 d6 c4 da 79 25 18 7d 82 d6 31 db 84 9a 61 e2 44 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}