rule k2319_13121eb9ca800b12 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=k2319.13121eb9ca800b12"
    cluster         = "k2319.13121eb9ca800b12"
    cluster_size    = "6"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "kryptik script diplugem"
    md5_hashes      = "['98700803f3101502d54d9ba960ea88f90b700781','b19d305966ba1bc4fe6b84b61de7db0430bc2e13','47720853ef6fc912e24fcda90c6e92e543fdaccb']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=k2319.13121eb9ca800b12"

  strings:
    $hex_string = "0x20D)?(75.,119):(73.3E1,91.)))break};var l9Z7j={'W5j':function("

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}