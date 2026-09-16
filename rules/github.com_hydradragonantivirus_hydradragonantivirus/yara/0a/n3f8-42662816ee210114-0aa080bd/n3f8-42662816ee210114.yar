rule n3f8_42662816ee210114 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=n3f8.42662816ee210114"
    cluster         = "n3f8.42662816ee210114"
    cluster_size    = "219"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "banker androidos origin"
    md5_hashes      = "['6a3edafc554884b001f5c11329ff759f7f01df0f','58e6d0402544ccf0fec5e1e7db1ad1fa9dbd469e','a6d1236ecd27e6ff8abeaca3897f51bf540ecb91']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=n3f8.42662816ee210114"

  strings:
    $hex_string = { 08 02 54 60 c0 03 72 20 50 0f 70 00 70 51 64 09 76 32 28 d6 53 62 c2 03 9c 02 08 02 70 40 5f 09 26 13 5a 64 c2 03 28 e7 54 61 c1 03 71 10 39 0e 00 00 0c 00 72 30 4f 0f 71 00 28 dd 6e 10 30 06 }

  condition:
    filesize > 262144 and filesize < 1048576
    and $hex_string
}