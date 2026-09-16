rule o2319_2b9b96c9c4000b12 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=o2319.2b9b96c9c4000b12"
    cluster         = "o2319.2b9b96c9c4000b12"
    cluster_size    = "4"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180911"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "script coinhive coinminer"
    md5_hashes      = "['0fe643a3889ab66b859a6e35e75d37964c131646','46492bfe33668668d4df4cf47b73888ccabe75dd','be72d95f5ac16e67dfab964a54a20a026a5f5c2e']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=o2319.2b9b96c9c4000b12"

  strings:
    $hex_string = "cpHLJbDqf0Kh0Sq1ar9isdioItAKGw+MAKYMFhbF63CW438f0mg1R2O8EuXj/aOP"

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}