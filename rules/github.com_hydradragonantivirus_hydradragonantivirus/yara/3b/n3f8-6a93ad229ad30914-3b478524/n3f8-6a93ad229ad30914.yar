rule n3f8_6a93ad229ad30914 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=n3f8.6a93ad229ad30914"
    cluster         = "n3f8.6a93ad229ad30914"
    cluster_size    = "256"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180911"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "smforw androidos smsagent"
    md5_hashes      = "['acacc0e8b32751f933d9f0ffb7b7e9819c7e7fa6','0798a7a4d7d192bd3a4d417aefb53fdeb0bd8a0c','6d15b9d5c126943ff0c84edb7db851fe4718ca89']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=n3f8.6a93ad229ad30914"

  strings:
    $hex_string = { 07 0e 87 2d 6d 3c 87 78 78 02 22 2c 02 57 1d 69 9e 5a 96 01 12 13 4b 4b 5b 6a b4 b6 89 6b 01 13 0f 01 1c 11 78 a5 d2 b4 02 63 4a 00 a3 03 01 00 07 0e 69 96 5a 3c c3 f0 51 19 69 01 11 0d 00 b9 }

  condition:
    filesize > 262144 and filesize < 1048576
    and $hex_string
}