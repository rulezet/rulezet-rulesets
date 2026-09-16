rule ofc8_431521d4dec30932 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=ofc8.431521d4dec30932"
    cluster         = "ofc8.431521d4dec30932"
    cluster_size    = "8"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180909"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "smspay riskware shedun"
    md5_hashes      = "['14d5f32a14926b4f170fcdc59f3af982b1bd4d73','04fbec02c86dfb9c90e260bd90ae9ed663279fbe','ce381f0eacc29b26ec830bd8a7b338330262d844']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=ofc8.431521d4dec30932"

  strings:
    $hex_string = { 3a c1 05 88 10 84 79 00 c4 6e 26 0f 14 93 29 11 30 44 83 2f 15 68 7e c7 b8 7c e3 65 de af ac 0d 7d 5e ad ba c3 eb d5 70 a8 3e 2a 73 6d e8 fe 01 31 25 f0 ff 6b 80 dd 54 0b 34 04 9c b3 c6 43 1a }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}