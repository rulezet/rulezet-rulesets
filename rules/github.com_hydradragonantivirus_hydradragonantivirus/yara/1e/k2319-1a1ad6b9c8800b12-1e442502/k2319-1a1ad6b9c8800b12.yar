rule k2319_1a1ad6b9c8800b12 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=k2319.1a1ad6b9c8800b12"
    cluster         = "k2319.1a1ad6b9c8800b12"
    cluster_size    = "15"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "kryptik script diplugem"
    md5_hashes      = "['94b33fe93c48cd73c5b1734a72a22ac5246e5e09','4852d25f91bc68a15aafb1b5948ec4970c486127','871d7a21c1c1b8bce25a175810cb855f821ddac0']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=k2319.1a1ad6b9c8800b12"

  strings:
    $hex_string = ">1.55E2?(0x1A1,119):(0x1AA,136.0E1)))break};var S7b7N={'Y8J':\"co"

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}