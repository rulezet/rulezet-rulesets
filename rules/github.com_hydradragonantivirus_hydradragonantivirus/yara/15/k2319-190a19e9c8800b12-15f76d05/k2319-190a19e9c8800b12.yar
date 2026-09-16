rule k2319_190a19e9c8800b12 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=k2319.190a19e9c8800b12"
    cluster         = "k2319.190a19e9c8800b12"
    cluster_size    = "17"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "kryptik script diplugem"
    md5_hashes      = "['592b5659f8bee1bd79baef5d7cd450647cd5e55c','4540455f1aac18b047b2754ce869d422b5e25d15','2b0d72e381e7bce65765cc9b68ae1bec357acc10']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=k2319.190a19e9c8800b12"

  strings:
    $hex_string = "(17.90E1,111.)))break};var x0Y1={'e2x':\"rCo\",'N3':function(Z,X){"

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}