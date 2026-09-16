rule k2319_193118a9c8800b32 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=k2319.193118a9c8800b32"
    cluster         = "k2319.193118a9c8800b32"
    cluster_size    = "71"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "kryptik script diplugem"
    md5_hashes      = "['3b7eee23c0dabba29831a0cbc3f53d3958b54ed7','17a531debd2df5058e6875f5c0bdb5326c172357','6abee307e66193c2f7fc5ef1d52b0094d3e0dd11']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=k2319.193118a9c8800b32"

  strings:
    $hex_string = "E2,24.3E1)))break};var Q0z={'m1g':1E3,'a8D':\"/\",'U':function(z,d"

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}