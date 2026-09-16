rule ofc8_6934c68cee608912 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=ofc8.6934c68cee608912"
    cluster         = "ofc8.6934c68cee608912"
    cluster_size    = "7"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180909"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "riskware smsreg androidos"
    md5_hashes      = "['2de1a5530cb47b97bd9c77fe83a8aa501e1367ea','d3ab3093754cd9914a53da9d8053e9c09744d2df','a02be0db2b7f78db185380a4462fdeaebe82bff6']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=ofc8.6934c68cee608912"

  strings:
    $hex_string = { f4 43 10 a6 8e 82 07 62 b9 b2 fd 86 a1 97 e2 09 58 01 7e da e3 32 4b 71 9e 2a 90 05 0a dc 1e d7 f3 d4 44 4f 2f d2 72 48 af 53 b7 91 a8 65 4a ef 56 46 68 78 1a 47 db de ad 39 f1 bf 87 bb a9 e9 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}