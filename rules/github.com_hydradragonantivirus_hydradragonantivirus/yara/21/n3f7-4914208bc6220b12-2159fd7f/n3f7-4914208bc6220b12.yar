rule n3f7_4914208bc6220b12 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=n3f7.4914208bc6220b12"
    cluster      = "n3f7.4914208bc6220b12"
    cluster_size = "23"
    filetype     = "text/html"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171122"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "clicker faceliker script"
    md5_hashes   = "['0168747c915e4b442c2e92319614f857','0d0e16f88ede97cf24833c282b024858','b998778d70481f3118322220868e8f67']"

  strings:
    $hex_string = ": 'Loading\\x26hellip;'}, 'displayModeFull'));\n_WidgetManager._Re"

  condition:
    filesize > 262144 and filesize < 1048576
    and $hex_string
}