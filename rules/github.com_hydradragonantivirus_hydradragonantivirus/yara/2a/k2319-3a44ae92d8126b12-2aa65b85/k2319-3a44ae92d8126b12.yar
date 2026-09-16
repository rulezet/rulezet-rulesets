rule k2319_3a44ae92d8126b12 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=k2319.3a44ae92d8126b12"
    cluster         = "k2319.3a44ae92d8126b12"
    cluster_size    = "5"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "kryptik script aknjt"
    md5_hashes      = "['2301966fdf3a42be8561c6b32935414790b20683','af7ff9f602318eb8ca31281d804adeb5c47d1d31','1a5d427ce20b89a5b854348e77159ea2fcfb71da']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=k2319.3a44ae92d8126b12"

  strings:
    $hex_string = "J]!==undefined){return o[J];}var r=((59.,98.0E1)>=(0x17,86.4E1)?"

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}