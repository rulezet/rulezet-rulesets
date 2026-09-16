rule k2319_3606ec4dcd527b12 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=k2319.3606ec4dcd527b12"
    cluster         = "k2319.3606ec4dcd527b12"
    cluster_size    = "5"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "kryptik script fffazo"
    md5_hashes      = "['142b76c4740646c2cf6d6e3957bf9cb80e130ce1','20e4c3690a37bd85b6eb8301f563ed5149584ef6','53785ddea23a1f62540a931871351a181529a811']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=k2319.3606ec4dcd527b12"

  strings:
    $hex_string = "?(5.82E2,119):(35,125.)))break};var Q0Q7Y={'p5G':\"0\",'v3G':\"figu"

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}