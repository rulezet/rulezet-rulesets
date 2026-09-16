rule k2319_393594b9c8800932 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=k2319.393594b9c8800932"
    cluster         = "k2319.393594b9c8800932"
    cluster_size    = "55"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "kryptik script diplugem"
    md5_hashes      = "['b5527670efb283bc164ec54d5171c63ff8e80903','f9ca79428d9ab56b6ac36203da9630d456139b5c','32a398e10c15c8c3bd2f9c74606640eeaef02151']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=k2319.393594b9c8800932"

  strings:
    $hex_string = "[R]!==undefined){return S[R];}var L=((118,0x7A)>(136.4E1,95.)?(0"

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}