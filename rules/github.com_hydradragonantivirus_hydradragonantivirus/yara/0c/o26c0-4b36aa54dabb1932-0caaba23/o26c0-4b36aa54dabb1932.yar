rule o26c0_4b36aa54dabb1932 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=o26c0.4b36aa54dabb1932"
    cluster         = "o26c0.4b36aa54dabb1932"
    cluster_size    = "29"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180909"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "graftor dlassistant heuristic"
    md5_hashes      = "['1fe27f2db44a5e9fe6d55b41fcfcf92c1f849dad','a9756dfd871ea122563294a2096aa82715db6cd4','90a9bde2b5c81fd3647530b7155f87a6ac93fd5e']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=o26c0.4b36aa54dabb1932"

  strings:
    $hex_string = { e8 94 95 24 f5 b6 c2 19 54 09 6f 90 ca f6 bb 32 d4 c1 07 a1 af 52 11 8b 4d 23 87 6e f1 ed d8 bd 4f c3 66 88 ad 73 0f 84 27 e7 46 1f 64 d3 cb 9e fa 7e 0b 26 3a b7 1a 75 f7 de db 1b 68 3f 2c be }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}