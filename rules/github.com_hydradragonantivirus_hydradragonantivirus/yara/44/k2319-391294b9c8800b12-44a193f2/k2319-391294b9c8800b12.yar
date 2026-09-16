rule k2319_391294b9c8800b12 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=k2319.391294b9c8800b12"
    cluster         = "k2319.391294b9c8800b12"
    cluster_size    = "9"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "kryptik script diplugem"
    md5_hashes      = "['baae664ab7819b17c1d5a86f8b46ded058829d88','5fce1fa443fbb5651e5727425e929695eca69202','fdb8a779134dc0ca80f421244d43776a0f7edc88']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=k2319.391294b9c8800b12"

  strings:
    $hex_string = "!==undefined){return D[e];}var P=((0x1AD,4.62E2)>(0x111,82.)?(35"

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}