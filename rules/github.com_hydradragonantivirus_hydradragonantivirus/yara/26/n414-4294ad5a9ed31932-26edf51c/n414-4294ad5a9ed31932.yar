rule n414_4294ad5a9ed31932 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=n414.4294ad5a9ed31932"
    cluster         = "n414.4294ad5a9ed31932"
    cluster_size    = "50"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180911"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "razy malicious filerepmalware"
    md5_hashes      = "['55d021b47ba04d79b1ae4dff34fd91a31a6328c9','7d682fe2bf90a75c449e5a61e1f27531dc5d79c0','7dc80596fe1f4e9af974932373e6f83aef0ddca9']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=n414.4294ad5a9ed31932"

  strings:
    $hex_string = { 44 f0 bc 55 b5 8c 50 b3 ef 3f ed 13 db 7a 54 99 91 fb 69 7d 41 a7 7f 9d 29 fe 83 68 73 2a 25 63 42 23 dc 6f fa 4c cb c3 e4 e7 c9 11 95 e8 09 51 06 7b 0e 60 e3 8d 3e 12 e9 b6 b2 c8 8b ca ff a9 }

  condition:
    filesize > 262144 and filesize < 1048576
    and $hex_string
}