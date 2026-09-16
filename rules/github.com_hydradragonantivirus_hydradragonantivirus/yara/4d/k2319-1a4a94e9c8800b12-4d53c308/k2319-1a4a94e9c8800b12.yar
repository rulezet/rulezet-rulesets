rule k2319_1a4a94e9c8800b12 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=k2319.1a4a94e9c8800b12"
    cluster         = "k2319.1a4a94e9c8800b12"
    cluster_size    = "6"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "kryptik script diplugem"
    md5_hashes      = "['3787b50d24d82191772989c17798d54243965195','eb9699c74328c9aaa2732e6dd90d0f570275b925','28244c5ea23fb4c2c29231a25699dcb3e13cfb41']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=k2319.1a4a94e9c8800b12"

  strings:
    $hex_string = "T[y]!==undefined){return T[y];}var V=(114.>=(90,39.)?(5.54E2,0xc"

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}