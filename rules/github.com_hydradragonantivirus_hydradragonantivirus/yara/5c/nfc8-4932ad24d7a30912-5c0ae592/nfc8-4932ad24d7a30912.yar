rule nfc8_4932ad24d7a30912 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=nfc8.4932ad24d7a30912"
    cluster         = "nfc8.4932ad24d7a30912"
    cluster_size    = "4"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180911"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "nymaim razy bfhh"
    md5_hashes      = "['602d4d7303d7b196e079f34e2b48864b689787a9','9475c86d7eb0dafa9f9d0ad30d0301704d557204','cd1d8f66b0884cb5c958e0c5f19aff3c7d6e697c']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=nfc8.4932ad24d7a30912"

  strings:
    $hex_string = { f8 c2 24 fa 6d 5a c9 c8 d8 7e 9b c6 20 d7 34 c7 07 43 a4 83 11 7d 14 b1 d4 fc 25 0e 58 b4 12 53 ec 9f 3c 1b 37 79 d1 01 29 de fb e5 f3 df b8 c0 0b f6 5e 8e 57 af f7 bc 27 a6 5c 97 69 33 50 1a }

  condition:
    filesize > 262144 and filesize < 1048576
    and $hex_string
}