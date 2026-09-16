rule o26bb_630da120dfa30912 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=o26bb.630da120dfa30912"
    cluster         = "o26bb.630da120dfa30912"
    cluster_size    = "25"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180909"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "bundler malicious heuristic"
    md5_hashes      = "['e2b3a8113dec9589c0ddbcc32fdebb550608774c','9b41b7276fd28883edfd2c689b088a98ffef0912','581bc7cc61667a04a7b05ffba0cf193cdd9d0e9c']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=o26bb.630da120dfa30912"

  strings:
    $hex_string = { 11 11 00 16 16 16 00 1c 1c 1c 00 22 22 22 00 29 29 29 00 55 55 55 00 4d 4d 4d 00 42 42 42 00 39 39 39 00 ff 7c 80 00 ff 50 50 00 d6 00 93 00 cc ec ff 00 ef d6 c6 00 e7 e7 d6 00 ad a9 90 00 33 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}