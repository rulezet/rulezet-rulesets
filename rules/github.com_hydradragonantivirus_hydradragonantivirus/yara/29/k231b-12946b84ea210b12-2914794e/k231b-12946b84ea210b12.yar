rule k231b_12946b84ea210b12 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=k231b.12946b84ea210b12"
    cluster         = "k231b.12946b84ea210b12"
    cluster_size    = "3"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "likejack faceliker script"
    md5_hashes      = "['fa3f7e85b3d3d9e540012a388a00a9b3b17c8d0b','a4b53a785c3ce4a5da285bdd124f6742c610524b','a4b0dfa40aa2e3a2c57ebcfe3a2f4459d50cb91c']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=k231b.12946b84ea210b12"

  strings:
    $hex_string = "y-v1\" content=\"RpuzsAd0ofFwNLTs6Giwf/EJCmx3wZKxo+UOXPj66Iw=\" />\n"

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}