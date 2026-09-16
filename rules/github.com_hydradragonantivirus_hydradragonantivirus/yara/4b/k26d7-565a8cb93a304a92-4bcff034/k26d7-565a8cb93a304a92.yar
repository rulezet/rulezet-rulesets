rule k26d7_565a8cb93a304a92 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=k26d7.565a8cb93a304a92"
    cluster         = "k26d7.565a8cb93a304a92"
    cluster_size    = "242"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "hmlwco malicious riskware"
    md5_hashes      = "['dc761813e6f46116ab080aff610c061461b16f98','5b2fd6607269b775ae1cb0c54fd21080000b29f0','2b995c556b1289200c6e4f2b4789be035da46e1f']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=k26d7.565a8cb93a304a92"

  strings:
    $hex_string = { 33 c0 85 c9 57 7e 1c 8b 7e 04 0f b7 57 02 39 55 0c 75 08 0f b6 17 39 55 fc 74 25 40 83 c7 06 3b c1 7c e7 8d 41 01 83 f8 01 89 46 10 75 23 6a 06 6a 00 ff 35 f8 b0 40 00 ff 15 e0 a6 40 00 eb 26 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}