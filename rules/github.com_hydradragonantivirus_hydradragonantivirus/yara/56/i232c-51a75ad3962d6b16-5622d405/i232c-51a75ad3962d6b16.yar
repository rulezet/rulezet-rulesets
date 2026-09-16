rule i232c_51a75ad3962d6b16 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=i232c.51a75ad3962d6b16"
    cluster         = "i232c.51a75ad3962d6b16"
    cluster_size    = "3"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "html phishing phish"
    md5_hashes      = "['801e544da6cbf1647dde273d3e7a1e64a61fd258','6bb3e570ec433a8f3019976a71b4cae62a1c732c','52f1b600ecce853ab0fd4dcd00ba38d15b916a02']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=i232c.51a75ad3962d6b16"

  strings:
    $hex_string = "PUBLIC \"-//W3C//DTD HTML 4.01 Transitional//EN\">\r\n<html>\r\n<head>"

  condition:
    filesize > 1024 and filesize < 4096
    and $hex_string
}