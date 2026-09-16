rule k26bf_2b9496fb48001110 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=k26bf.2b9496fb48001110"
    cluster         = "k26bf.2b9496fb48001110"
    cluster_size    = "4"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "razy malicious attribute"
    md5_hashes      = "['aec0888dd9bd834e0f555e62cb4a2912bbf8e685','e840a8432ed3db711812dbf9cd0d04b911e699e7','6d07ba9c2e50d61f9ac28afbbf2aa10674747c87']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=k26bf.2b9496fb48001110"

  strings:
    $hex_string = { 28 2d 00 00 0a 17 0b 18 0d 03 47 2c 76 19 0d 73 36 00 00 0a 13 04 1a 0d 11 04 17 17 73 3f 00 00 0a 13 05 1b 0d 11 05 02 16 02 8e 69 6f 40 00 00 0a 1c 0d 11 05 6f 3c 00 00 0a 1d 0d 11 04 16 6a }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}