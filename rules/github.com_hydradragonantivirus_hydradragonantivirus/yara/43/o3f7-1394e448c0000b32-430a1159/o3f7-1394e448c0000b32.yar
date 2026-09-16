rule o3f7_1394e448c0000b32 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=o3f7.1394e448c0000b32"
    cluster      = "o3f7.1394e448c0000b32"
    cluster_size = "62"
    filetype     = "text/html"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171122"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "script faceliker clicker"
    md5_hashes   = "['013bfcc1b5194d17856c90cbeffaec50','04dcde6d2b02693e1d887d3b095f6874','43caa16d8538207714e60c61de867f3c']"

  strings:
    $hex_string = "ElementById('HTML5'), {}, 'displayModeFull'));\n_WidgetManager._R"

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}