rule o3f7_4394e448c0000b32 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=o3f7.4394e448c0000b32"
    cluster      = "o3f7.4394e448c0000b32"
    cluster_size = "219"
    filetype     = "text/html"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171122"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "script faceliker clicker"
    md5_hashes   = "['002f0c4ca99afca3751dbddededcb75f','026d142c4351dd6fb004fbbea514950e','1534f46b405d46531918654ba9656a6f']"

  strings:
    $hex_string = "ElementById('HTML3'), {}, 'displayModeFull'));\n_WidgetManager._R"

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}