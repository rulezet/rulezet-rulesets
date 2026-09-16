rule n3f8_6ab3ad229ad30914 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=n3f8.6ab3ad229ad30914"
    cluster         = "n3f8.6ab3ad229ad30914"
    cluster_size    = "36"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180911"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "androidos smforw smssend"
    md5_hashes      = "['7e03cb6fab16f63b94d3b7952f5cc209796dc274','b67f8db324cfe2b247f7c7658e1b1978e4e5d3f7','a2a3eb241054fdf5e99e20ae97f96bd64aaf48db']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=n3f8.6ab3ad229ad30914"

  strings:
    $hex_string = { 54 cc 1f 01 01 4d 44 0c 0c 0d 6e 20 33 15 cb 00 0c 0b 6e 10 3c 15 0b 00 0c 0b 70 20 f8 14 ba 00 70 20 ba 03 98 00 07 58 12 19 5c 89 a3 00 63 08 fd 00 38 08 2a 00 1a 08 fb 02 22 09 28 03 07 9e }

  condition:
    filesize > 262144 and filesize < 1048576
    and $hex_string
}