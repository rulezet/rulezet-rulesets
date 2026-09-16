rule o26c9_419b3689c8000b12 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=o26c9.419b3689c8000b12"
    cluster         = "o26c9.419b3689c8000b12"
    cluster_size    = "8"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180909"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "unsafe gamehack malicious"
    md5_hashes      = "['a4a062d5c8c33b41aa2e240f958f110b2b5eb4ad','0bd536461dfed299ec49b7e09120037e4cd1d691','2706ebf9f92b64c46b6ffd2c396fafc784b9f7d3']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=o26c9.419b3689c8000b12"

  strings:
    $hex_string = { bf 3a 7a f7 66 94 91 32 33 a2 26 43 f6 27 9b 10 a3 ca 2d 3b 9d 76 d7 58 7b 6d 31 db 11 22 d3 1e fb bd 74 0f bb 59 d9 83 d8 52 72 6a d2 dd f2 ee 87 62 69 6e a8 f9 8d 65 08 8b e9 2c 1c 5d ef 02 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}