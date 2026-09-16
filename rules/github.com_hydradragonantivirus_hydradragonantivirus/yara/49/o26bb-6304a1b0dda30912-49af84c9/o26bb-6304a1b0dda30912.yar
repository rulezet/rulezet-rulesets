rule o26bb_6304a1b0dda30912 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=o26bb.6304a1b0dda30912"
    cluster         = "o26bb.6304a1b0dda30912"
    cluster_size    = "34"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180909"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "bundler malicious heuristic"
    md5_hashes      = "['8d007248ba615ba4af8599bc3a0b01ce101fca10','038012e2bcfa83f493f9d5c985b377cc9eb451f0','3896f69ed08c80483cfaadca06363c83e729ba04']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=o26bb.6304a1b0dda30912"

  strings:
    $hex_string = { c7 8d bb d9 02 6f 67 0b c8 8b 5d ac 03 4d d8 81 c3 8a 4c 2a 8d 03 f9 8b ca c1 c7 0e f7 d1 03 fe 23 ce 8b c7 23 c2 0b c8 8b c6 03 4d ec 33 c7 03 d9 c1 cb 0c 03 df 33 c3 05 42 39 fa ff 03 45 d0 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}