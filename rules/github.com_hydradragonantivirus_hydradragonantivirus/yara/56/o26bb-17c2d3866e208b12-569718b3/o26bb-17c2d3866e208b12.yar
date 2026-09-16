rule o26bb_17c2d3866e208b12 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=o26bb.17c2d3866e208b12"
    cluster         = "o26bb.17c2d3866e208b12"
    cluster_size    = "61"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "gamehack malicious unsafe"
    md5_hashes      = "['7dce6c525ee57cdb423dcbd26b4f4811261a5d58','29d83c3825c912c9fcd00e372c9b88ec5b341246','ddc9dae699562947b705a1e51879af3fa4131bb3']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=o26bb.17c2d3866e208b12"

  strings:
    $hex_string = { 44 ba 69 93 80 c2 19 28 43 18 06 83 95 29 86 04 42 dc 11 c0 70 13 0d 55 77 5d a7 3e 41 9a 7e bd 98 25 9e 53 30 b1 22 1f 65 e4 e5 6d 2c ae 62 92 f4 72 ac 90 4f 01 97 8d d5 58 b8 5a d1 66 f0 c1 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}