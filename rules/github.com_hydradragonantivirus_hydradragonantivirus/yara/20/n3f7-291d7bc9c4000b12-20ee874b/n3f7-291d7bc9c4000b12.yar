rule n3f7_291d7bc9c4000b12 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=n3f7.291d7bc9c4000b12"
    cluster      = "n3f7.291d7bc9c4000b12"
    cluster_size = "3"
    filetype     = "text/html"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171122"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "faceliker script html"
    md5_hashes   = "['379d4f484598695d8882a6dcca92039d','48120abf8c0ede299cdf673a09a6aef7','63891f62c18097c78263fd651e15faab']"

  strings:
    $hex_string = "ElementById('HTML3'), {}, 'displayModeFull'));\n_WidgetManager._R"

  condition:
    filesize > 262144 and filesize < 1048576
    and $hex_string
}