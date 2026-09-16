rule k2319_185294b9ca800b12 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=k2319.185294b9ca800b12"
    cluster         = "k2319.185294b9ca800b12"
    cluster_size    = "4"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "kryptik script diplugem"
    md5_hashes      = "['39d194eee025c6449aab62ba1ff207cca914e83a','4680b340d0ef04647b175ee61728783cb0637c39','b92fc30c06d0819195a93bb9835d3ef52bee2ea6']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=k2319.185294b9ca800b12"

  strings:
    $hex_string = "k};for(var X6L in O8g6L){if(X6L.length===((34.2E1,0x1AD)>=(0x15A"

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}