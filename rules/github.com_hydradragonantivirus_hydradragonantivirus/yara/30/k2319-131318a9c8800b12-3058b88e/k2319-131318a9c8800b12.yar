rule k2319_131318a9c8800b12 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=k2319.131318a9c8800b12"
    cluster         = "k2319.131318a9c8800b12"
    cluster_size    = "5"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "kryptik script diplugem"
    md5_hashes      = "['5fbdd7d52c1b4e3ab4b86dd4abe94ac23c6978c1','b97f283be9a89e8de96a4d7784bff0c8bc4a965d','5e240fe0d302bc572079105418c2e01bba8fc3a0']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=k2319.131318a9c8800b12"

  strings:
    $hex_string = "P[J]!==undefined){return P[J];}var N=((1.1E1,90)>=59?(9.36E2,0xc"

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}