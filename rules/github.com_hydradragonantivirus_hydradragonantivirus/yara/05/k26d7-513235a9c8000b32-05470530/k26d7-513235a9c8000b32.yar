rule k26d7_513235a9c8000b32 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=k26d7.513235a9c8000b32"
    cluster         = "k26d7.513235a9c8000b32"
    cluster_size    = "140"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "java genericgb keylogger"
    md5_hashes      = "['d6ff8ef9c42ad7151d9df1b682511525fd418f9e','a1faee7eeb3d82acbd5d21911d1e31c1d356c8c0','279bdbb300d595f2369b4f5096bbef396377a4b6']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=k26d7.513235a9c8000b32"

  strings:
    $hex_string = { ec 18 8b 75 f0 85 c0 0f 94 c1 0f b6 f9 89 7d e8 89 34 24 e8 78 36 00 00 83 ec 04 c6 43 ff 5c 8b 45 e8 8d 65 f4 5b 5e 5f 5d c3 89 7c 24 04 31 c9 8d 55 f0 89 54 24 10 b8 19 01 02 00 89 44 24 0c }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}