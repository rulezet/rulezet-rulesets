rule j2318_611dea48c0000932 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=j2318.611dea48c0000932"
    cluster      = "j2318.611dea48c0000932"
    cluster_size = "4"
    filetype     = "text/html"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171118"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "iframe html iframeref"
    md5_hashes   = "['67d3c6836e617e343bdbbf2a33ac1a1f','d08ce3706f0aeb705a11cebde51ccdbd','fb4b86b3ebc41641bb20fd91143d3841']"

  strings:
    $hex_string = "45 src=http://nmsbaseball.com/post.php?id=666088></iframe></body"

  condition:
    filesize > 4096 and filesize < 16384
    and $hex_string
}