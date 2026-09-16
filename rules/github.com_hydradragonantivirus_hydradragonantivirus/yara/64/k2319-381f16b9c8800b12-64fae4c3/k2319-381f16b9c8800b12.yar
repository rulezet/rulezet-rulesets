rule k2319_381f16b9c8800b12 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=k2319.381f16b9c8800b12"
    cluster         = "k2319.381f16b9c8800b12"
    cluster_size    = "94"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "kryptik script diplugem"
    md5_hashes      = "['316de9e1fe642ad467332b42d9d04c54658a1824','0408707ecf7c4f0659d0037831d70bb2eef36d53','a8d198ae5808bb9c4b888b8214a7d1275acd53ca']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=k2319.381f16b9c8800b12"

  strings:
    $hex_string = "W,N,z){if(A[z]!==undefined){return A[z];}var S=((0xF9,37.)>(122."

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}