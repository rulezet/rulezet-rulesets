rule k2319_2107514b86220932 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=k2319.2107514b86220932"
    cluster         = "k2319.2107514b86220932"
    cluster_size    = "15"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "multiplug kryptik diplugem"
    md5_hashes      = "['c3493863ddb49262fa9050d6d217910c0fcd2933','9ae933658069fd6dfb0fb92de724ac0e5fc3c180','00de9ddf9909a48c2beca350fa8dddf6af398a68']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=k2319.2107514b86220932"

  strings:
    $hex_string = "2):(13.05E2,96.)))break};var L7S1h={'q6l':\"h\",'Y9B':function(M,Q"

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}