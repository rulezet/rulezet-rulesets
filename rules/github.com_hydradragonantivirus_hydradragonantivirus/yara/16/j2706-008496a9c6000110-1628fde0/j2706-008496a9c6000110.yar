rule j2706_008496a9c6000110 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=j2706.008496a9c6000110"
    cluster         = "j2706.008496a9c6000110"
    cluster_size    = "1095"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "linkury unwanted dknlqw"
    md5_hashes      = "['c21f13f65061a408a4fd94a8e6c5026acefed879','75c6ded382c886cd984b8c2cf510694e32a73e6f','872b71fb74ecab1d8fdf805fb4a2df6562dc73f2']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=j2706.008496a9c6000110"

  strings:
    $hex_string = { 0a 2d 24 06 6f 21 00 00 0a 02 7b 05 00 00 04 33 0e 06 6f 22 00 00 0a 02 7b 04 00 00 04 2e 08 02 06 28 23 00 00 0a 7a 07 2c 02 14 2a 73 33 00 00 0a 0c 17 8d 17 00 00 01 0d 2b 61 09 16 90 2d 3d }

  condition:
    filesize > 4096 and filesize < 16384
    and $hex_string
}