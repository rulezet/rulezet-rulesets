rule k2319_1a5a1ab9c9000912 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=k2319.1a5a1ab9c9000912"
    cluster         = "k2319.1a5a1ab9c9000912"
    cluster_size    = "10"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "kryptik script diplugem"
    md5_hashes      = "['735337222469c6f6c223fede8fa7513141d5c8c3','44f77e5034ca0aadc87d426a981ec3ad2357e8be','26efbdb9a1f43b9951c9a0bac991a08c457950a9']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=k2319.1a5a1ab9c9000912"

  strings:
    $hex_string = "?(0xC9,119):(7.72E2,0x1E7)))break};var S2e8={'g8':function(B,P){"

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}