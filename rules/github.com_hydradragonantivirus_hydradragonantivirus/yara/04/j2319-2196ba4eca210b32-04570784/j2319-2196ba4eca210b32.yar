rule j2319_2196ba4eca210b32 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=j2319.2196ba4eca210b32"
    cluster      = "j2319.2196ba4eca210b32"
    cluster_size = "5"
    filetype     = "text/html"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "fakejquery redirector html"
    md5_hashes   = "['1c8d5d08252f384efb3446bbfe98ad83','4d0543a949c736cccaa08fdba1bfd7a5','f081e897eb32ea05b28c187f146e2d11']"

  strings:
    $hex_string = "l/js/jquery.min.php'+'?'+'default_keyword='+encodeURIComponent(("

  condition:
    filesize > 4096 and filesize < 16384
    and $hex_string
}