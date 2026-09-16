rule j2319_4996549bc6220b32 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=j2319.4996549bc6220b32"
    cluster         = "j2319.4996549bc6220b32"
    cluster_size    = "5"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "nemucod script dloadr"
    md5_hashes      = "['45bdba011286216137628c44404a437d4ff7b971','952829d60b1330cf8577654550aaac85a94d6219','77c76b068108a917e65480011302855cbff671ee']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=j2319.4996549bc6220b32"

  strings:
    $hex_string = "EbAY/gW2xS3visdQFkFLSU2K5bcQEB3t7sWaQozuht4SXgn5r9lKBcqJMNl+wd\nO"

  condition:
    filesize > 4096 and filesize < 16384
    and $hex_string
}