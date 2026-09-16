rule j2319_6999d6b9c8800b32 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=j2319.6999d6b9c8800b32"
    cluster         = "j2319.6999d6b9c8800b32"
    cluster_size    = "20"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "mplug diplugem script"
    md5_hashes      = "['907c01e2624cf1e8ea85aa9bf96fe1abcc4d8ae0','2621c2a4f30ace666dec95ac4fc8779a207b4314','3d54f89b3f22a6c7c7f35676247153540b9032df']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=j2319.6999d6b9c8800b32"

  strings:
    $hex_string = "}\n\t}\n\tmng.successful=1;\n\ttry{if(!jscr){tga.track('/firefox/BugEx"

  condition:
    filesize > 4096 and filesize < 16384
    and $hex_string
}