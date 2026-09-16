rule k2319_111b14b9c2200b32 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k2319.111b14b9c2200b32"
    cluster      = "k2319.111b14b9c2200b32"
    cluster_size = "7"
    filetype     = "text/html"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "fakejquery classic eiframetrojanjquery"
    md5_hashes   = "['12a3c0358eeefb9f18fba073f79a8b72','59bd4d653807041ae5e58228143012e6','fef266a4f5d43927fa96d06489b512eb']"

  strings:
    $hex_string = "me()+60*c*60*1e3);var e=\"expires=\"+d.toUTCString();document.cook"

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}