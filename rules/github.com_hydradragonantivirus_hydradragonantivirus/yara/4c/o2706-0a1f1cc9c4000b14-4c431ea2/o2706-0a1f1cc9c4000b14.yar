rule o2706_0a1f1cc9c4000b14 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=o2706.0a1f1cc9c4000b14"
    cluster         = "o2706.0a1f1cc9c4000b14"
    cluster_size    = "28"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180909"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "browsefox ursu injector"
    md5_hashes      = "['97e81b471d70b83e6ce069d65bd8c9473ccd49b8','9bf0d091b15bccd25f5a84461bce0ca456d39623','201147b17e37a2e8184b92daeb4d61d1af3f4cb0']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=o2706.0a1f1cc9c4000b14"

  strings:
    $hex_string = { 2e 4a 73 6f 6e 2e 4c 69 6e 71 2e 4a 54 6f 6b 65 6e 3e 3e 2e 67 65 74 5f 49 73 52 65 61 64 4f 6e 6c 79 00 63 37 64 66 34 37 37 31 39 32 61 65 66 61 38 34 65 36 61 63 39 32 30 36 35 31 64 36 35 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}