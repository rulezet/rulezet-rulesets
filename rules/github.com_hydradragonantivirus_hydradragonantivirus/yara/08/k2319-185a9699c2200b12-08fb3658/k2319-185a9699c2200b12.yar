rule k2319_185a9699c2200b12 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=k2319.185a9699c2200b12"
    cluster         = "k2319.185a9699c2200b12"
    cluster_size    = "59"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "kryptik script diplugem"
    md5_hashes      = "['02bb6112324340cbad1cc7f9e978718526f48c5d','c22fab42105562f5584e5d07b3a787da4a50161a','3dad77f407f88c79d181b25a14cbb8af3bf06169']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=k2319.185a9699c2200b12"

  strings:
    $hex_string = "<=135.?(19,1):(6.53E2,126.)))break};var r5a3p={'G4p':function(U,"

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}