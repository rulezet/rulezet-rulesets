rule o26bf_09997ac1c8000b12 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=o26bf.09997ac1c8000b12"
    cluster         = "o26bf.09997ac1c8000b12"
    cluster_size    = "5"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180909"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "temonde malicious adload"
    md5_hashes      = "['a5fa621135c3af1f92488d47b7da12ca56304a5c','5b81d88f6caf8afbd06b748bcfeca6ce4e89afd6','bd5913c81880421be976937e3c27375fec2a93fe']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=o26bf.09997ac1c8000b12"

  strings:
    $hex_string = { 23 44 3c e0 13 1f ff 4d de f5 f6 77 71 fe fc 3a 0f 3f f3 08 ef f8 a6 fb 69 d6 ca b4 ea 0d 5a d5 32 42 1a 4a be 47 a3 dd c0 84 25 fa 52 b0 31 8c 11 95 10 21 7d db 70 c4 93 28 6c 5c c2 78 bd 88 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}