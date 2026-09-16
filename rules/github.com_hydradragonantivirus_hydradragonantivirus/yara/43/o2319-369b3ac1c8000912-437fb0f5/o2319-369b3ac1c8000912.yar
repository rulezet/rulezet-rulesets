rule o2319_369b3ac1c8000912 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=o2319.369b3ac1c8000912"
    cluster         = "o2319.369b3ac1c8000912"
    cluster_size    = "3"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180911"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "script coinminer coinhive"
    md5_hashes      = "['193b0d7a8e53fdda7218f38e540f7d883598df72','6058e2221fd67178edffafdb9ffe31acc3085ee6','3c4328578658413fcd7995efd36e1dba6d1254a0']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=o2319.369b3ac1c8000912"

  strings:
    $hex_string = "panoid=YJ0lq28OOy3VT2IqIuVY0g&cbp=12,151.58,,0,-15.56\n */\n(funct"

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}