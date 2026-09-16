rule o26bb_4966b1e948800912 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=o26bb.4966b1e948800912"
    cluster         = "o26bb.4966b1e948800912"
    cluster_size    = "5"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180909"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "nymeria malicious autoit"
    md5_hashes      = "['50b9610ff324cd02008a6a4a6b76d3c7895c292f','a97e00389105eab3b22dd151acbb98c4dc4df9ba','30ffa12e4f5844f0ed4958ec38f1be812db65654']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=o26bb.4966b1e948800912"

  strings:
    $hex_string = { f8 bf 60 51 4b 00 33 f6 b0 05 0f b6 d8 3b d3 75 13 52 8b d7 e8 3c 7f f9 ff 59 85 c0 74 1c 8b 55 fc 8b 4d f8 8a 86 01 4e 4b 00 47 03 fb 46 84 c0 75 d8 83 c8 ff 5f 5e 5b c9 c3 8b c6 eb f7 53 56 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}