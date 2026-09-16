rule k2319_23b51856cec2d131 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=k2319.23b51856cec2d131"
    cluster         = "k2319.23b51856cec2d131"
    cluster_size    = "6"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "fakejquery script iscp"
    md5_hashes      = "['f73b584ff17d3b0e439e390be61fe9ca74a1f966','75dd1f0a03a0e703d08688616c32a6b42935490a','491bef17a78f94229f55962038e27a642bee3d67']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=k2319.23b51856cec2d131"

  strings:
    $hex_string = "ipt'>\n/* <![CDATA[ */\nvar bwg_objectsL10n = {\"bwg_select_tag\":\"S"

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}