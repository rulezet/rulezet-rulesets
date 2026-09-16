rule k2319_392c14a9c8800932 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=k2319.392c14a9c8800932"
    cluster         = "k2319.392c14a9c8800932"
    cluster_size    = "11"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "kryptik script diplugem"
    md5_hashes      = "['59d2d609fd7edfaf606e01a1cb475cede20e27de','4bf63df386690b8653643112948134008e98a17c','788215bb192dc604cfb71d576a1f27e040c508fc']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=k2319.392c14a9c8800932"

  strings:
    $hex_string = "fined){return P[C];}var q=((40,66.5E1)<(0x7C,0x20A)?4:0xFB>(82.8"

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}