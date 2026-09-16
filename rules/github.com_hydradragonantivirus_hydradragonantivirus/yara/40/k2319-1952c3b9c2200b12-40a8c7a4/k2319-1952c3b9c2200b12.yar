rule k2319_1952c3b9c2200b12 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=k2319.1952c3b9c2200b12"
    cluster         = "k2319.1952c3b9c2200b12"
    cluster_size    = "3"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "kryptik script diplugem"
    md5_hashes      = "['6bc62af822200ae8c54b89bdea0c060425af1d4d','f0c50fcff660b08f28c9966554f37e0c1de5803c','28aecba76f91f0b85ef3494357c8764537deaf67']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=k2319.1952c3b9c2200b12"

  strings:
    $hex_string = "fined){return T[l];}var F=(6.03E2<=(0x1C6,52)?(90,133):(0x24,81."

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}