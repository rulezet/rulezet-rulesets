rule k2319_1a159699c2200b12 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=k2319.1a159699c2200b12"
    cluster         = "k2319.1a159699c2200b12"
    cluster_size    = "40"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "kryptik script diplugem"
    md5_hashes      = "['5429d903ad4b50cb9619822e7e1b349e329c22c4','63ef9cd4ed81fcf47d48b855be1c55e556fbee2e','0be87988dae1a38f71f7f7775b33a579329f25ae']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=k2319.1a159699c2200b12"

  strings:
    $hex_string = "f(b9[L]!==undefined){return b9[L];}var A=(7.46E2<=(93,7.2E1)?83:"

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}