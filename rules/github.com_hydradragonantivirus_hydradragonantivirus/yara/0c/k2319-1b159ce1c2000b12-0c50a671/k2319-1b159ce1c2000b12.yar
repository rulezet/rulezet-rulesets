rule k2319_1b159ce1c2000b12 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=k2319.1b159ce1c2000b12"
    cluster         = "k2319.1b159ce1c2000b12"
    cluster_size    = "5"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "kryptik script diplugem"
    md5_hashes      = "['c3415e65c91937b21107c7e8f6f151fe7c6bed8a','99e60bd7ad4a2ec2e29e02632a2935b28f54a31e','15ef1c088c7311d4787b7e3151b7f170ec9c1e42']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=k2319.1b159ce1c2000b12"

  strings:
    $hex_string = "!==undefined){return G[S];}var p=((0x5B,26)<=50.7E1?(4.39E2,0xcc"

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}