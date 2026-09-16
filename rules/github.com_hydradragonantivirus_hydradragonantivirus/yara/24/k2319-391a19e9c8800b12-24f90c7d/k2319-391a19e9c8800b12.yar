rule k2319_391a19e9c8800b12 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=k2319.391a19e9c8800b12"
    cluster         = "k2319.391a19e9c8800b12"
    cluster_size    = "13"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "kryptik script diplugem"
    md5_hashes      = "['ad11b363be4aa581ab8f4c3db9db2e8ba3516377','1c18dc4fb59e109c91c58058d2b3a3dbe742ccc3','8bd096147f3f5d0b76a741748e1a3a9bf716ecb7']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=k2319.391a19e9c8800b12"

  strings:
    $hex_string = ")break};for(var V5k in u0g5k){if(V5k.length===(143.6E1<(9.20E1,3"

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}