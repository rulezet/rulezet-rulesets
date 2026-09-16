rule k26bb_7ab24290dcbb0912 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=k26bb.7ab24290dcbb0912"
    cluster         = "k26bb.7ab24290dcbb0912"
    cluster_size    = "75"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "domaiq bundler nsis"
    md5_hashes      = "['0b6445de34f5e5b653cef970ac08a369103e499d','bacc395284f76c8d41aace2160f26d745071354a','cb905e79135014ee5e799736b5dceb4f7d4975b0']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=k26bb.7ab24290dcbb0912"

  strings:
    $hex_string = { f8 ff 15 2c 71 40 00 85 c0 74 65 83 7d d0 01 75 5f 39 5d e8 75 21 80 7d 0b 0d 74 2b 80 7d 0b 0a 74 25 8a 45 f7 88 04 3e 46 3a c3 88 45 0b 74 40 3b 75 cc 7c be eb 39 0f b6 45 f7 50 57 e8 31 35 }

  condition:
    filesize > 262144 and filesize < 1048576
    and $hex_string
}