rule nfc8_291e12b9c8800b32 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=nfc8.291e12b9c8800b32"
    cluster         = "nfc8.291e12b9c8800b32"
    cluster_size    = "93"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "banker androidos wroba"
    md5_hashes      = "['3e8bbf10dceaf97c224535a3ea3295e1b153a3eb','0758d747170ed18cd3e2b00f23a55c93bdd99217','19e563a10abe1a792fd8de41204ac3509603b7db']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=nfc8.291e12b9c8800b32"

  strings:
    $hex_string = { 2b ac 4e 6d 78 d1 ba 06 4c 08 6e 18 4f c6 b4 0d 80 d6 2d f4 9f 8a 9d 5a 47 c0 ab 6b 7d f3 19 c2 fc 85 a7 a8 b5 71 56 5f d7 0e 29 b6 65 1c 66 1d 52 b8 df 03 97 49 15 cf fa 90 12 7a 5c 23 2a d5 }

  condition:
    filesize > 262144 and filesize < 1048576
    and $hex_string
}