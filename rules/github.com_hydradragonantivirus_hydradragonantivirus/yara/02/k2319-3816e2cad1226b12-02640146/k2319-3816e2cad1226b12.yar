rule k2319_3816e2cad1226b12 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=k2319.3816e2cad1226b12"
    cluster         = "k2319.3816e2cad1226b12"
    cluster_size    = "3"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "kryptik script fffazo"
    md5_hashes      = "['6147493f19efa95cd9b8254ffdd45a5987ae7b2f','1fee6029f8dfc34e496637619edc7d0668f62d21','5247a9fc584b4958ba54f558664f37ff0f784852']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=k2319.3816e2cad1226b12"

  strings:
    $hex_string = "9):(109.60E1,65.)))break};var D5r1l={'F4U':\";\",'S8l':function(j,"

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}