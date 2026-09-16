rule j2341_6b9205a0db179912 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=j2341.6b9205a0db179912"
    cluster      = "j2341.6b9205a0db179912"
    cluster_size = "6"
    filetype     = "text/plain"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171118"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "derl hacktool rabased"
    md5_hashes   = "['3396f68d8f70910aba2eee1c9448374c','49e6b3000c1ca76f8ababc21f1572898','de94169cde03658924928657acac8651']"

  strings:
    $hex_string = "53,65,74,08,00,\\\r\n  00\r\n\"FUSClientPath\"=\"C:\\\\Program Files\\\\Remo"

  condition:
    filesize > 4096 and filesize < 16384
    and $hex_string
}