rule k2319_181296e9c8800b12 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=k2319.181296e9c8800b12"
    cluster         = "k2319.181296e9c8800b12"
    cluster_size    = "64"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "kryptik script diplugem"
    md5_hashes      = "['1c650ce938eabeec58b1f67e16bc0cd83a264dba','a243d8702dc6d06fc4a3bce7f4c76cdd05786a6e','87ebc61304adabbbb6f2142ee6a05292da2815db']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=k2319.181296e9c8800b12"

  strings:
    $hex_string = "xE5,100.)))break};var U2s={'G4D':\"cre\",'R9D':\"a\",'L6':function(T"

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}