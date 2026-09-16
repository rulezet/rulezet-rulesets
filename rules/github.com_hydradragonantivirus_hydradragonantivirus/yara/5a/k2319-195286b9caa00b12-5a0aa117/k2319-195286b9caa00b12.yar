rule k2319_195286b9caa00b12 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=k2319.195286b9caa00b12"
    cluster         = "k2319.195286b9caa00b12"
    cluster_size    = "9"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "kryptik script diplugem"
    md5_hashes      = "['2354eca17e5f99d61067e640e8df52af038e3a4c','abec95f8be9e1e5f1dc437143252d08a1400ca68','1c706d74c26e101486ee6a18544214bef506d34c']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=k2319.195286b9caa00b12"

  strings:
    $hex_string = "defined){return T[l];}var F=(6.03E2<=(0x1C6,52)?(90,133):(0x24,8"

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}