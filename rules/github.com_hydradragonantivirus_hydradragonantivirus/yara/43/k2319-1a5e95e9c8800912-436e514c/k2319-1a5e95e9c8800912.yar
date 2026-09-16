rule k2319_1a5e95e9c8800912 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=k2319.1a5e95e9c8800912"
    cluster         = "k2319.1a5e95e9c8800912"
    cluster_size    = "7"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "script kryptik diplugem"
    md5_hashes      = "['e7581b4442a75ebffb6739d25a35d6536a3264a9','5ff78c3a3da445b8a0ddc2368f6e1e08718c5752','e79507831950de7dcd11820da16c19f2bb643058']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=k2319.1a5e95e9c8800912"

  strings:
    $hex_string = "19):(0x20A,127.7E1)))break};var v6N1v={'R6n':\"j\",'O5v':function("

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}