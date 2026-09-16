rule k2319_181996a9c8800912 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=k2319.181996a9c8800912"
    cluster         = "k2319.181996a9c8800912"
    cluster_size    = "80"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "kryptik script diplugem"
    md5_hashes      = "['77a9ec7fc83aa5f0eb2fae9f0b7b8d196d663446','9419db4b51b4239a09f9f5b1dd1bce7df585aabe','5c639676a1087d3901ca80ea83a3f31101f4be66']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=k2319.181996a9c8800912"

  strings:
    $hex_string = "32.)?\"b\":(0x1E,140)))break};for(var w5B in P9N5B){if(w5B.length="

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}