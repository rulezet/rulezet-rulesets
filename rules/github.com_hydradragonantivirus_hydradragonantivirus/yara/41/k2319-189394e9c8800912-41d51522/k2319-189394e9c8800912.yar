rule k2319_189394e9c8800912 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=k2319.189394e9c8800912"
    cluster         = "k2319.189394e9c8800912"
    cluster_size    = "50"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "kryptik diplugem expkit"
    md5_hashes      = "['b49d881519e58b45c11297a5b599672083c52033','42f49d8fabb0323e3707985be142130bf1a6225b','395b5dfd704b177787bbc4c826e7de66e20f33ba']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=k2319.189394e9c8800912"

  strings:
    $hex_string = "efined){return N[R];}var H=((49.,1.031E3)>=0xFC?(0x1D1,0xcc9e2d5"

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}