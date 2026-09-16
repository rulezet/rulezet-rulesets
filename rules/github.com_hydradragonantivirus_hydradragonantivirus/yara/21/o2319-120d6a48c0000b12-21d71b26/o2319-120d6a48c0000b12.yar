rule o2319_120d6a48c0000b12 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=o2319.120d6a48c0000b12"
    cluster         = "o2319.120d6a48c0000b12"
    cluster_size    = "3"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "likejack faceliker html"
    md5_hashes      = "['bec044c48851cc3e6a3ceb4c8bab9008062bb0df','a269d5c322cdbd61277f591680c107f9605028b6','56b76e37bc55d431d5bee0467e504fe00b6c5f13']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=o2319.120d6a48c0000b12"

  strings:
    $hex_string = "tion(a){return a?a.replace(/[!\"$%&'()*+,.\\/:;<=>?@\\[\\]\\^`{|}~]/g"

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}