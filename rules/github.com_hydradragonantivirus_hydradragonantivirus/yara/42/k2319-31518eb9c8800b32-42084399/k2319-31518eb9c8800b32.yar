rule k2319_31518eb9c8800b32 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=k2319.31518eb9c8800b32"
    cluster         = "k2319.31518eb9c8800b32"
    cluster_size    = "9"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "kryptik script diplugem"
    md5_hashes      = "['1398b2a80930c786625a937eaf007b2e4227d00f','5a462b4b3043d36f5fd557205e160571b2b710c6','c87ff044449abde6326c40f65ec8c5d113ac3a4a']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=k2319.31518eb9c8800b32"

  strings:
    $hex_string = "!==undefined){return E[A];}var Q=((0xC2,6.7E1)<=(0x1F5,0x82)?(9."

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}