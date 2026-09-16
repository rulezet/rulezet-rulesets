rule k3e9_092b311e4b8a8912 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e9.092b311e4b8a8912"
    cluster      = "k3e9.092b311e4b8a8912"
    cluster_size = "112"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "jeefo hidrag adload"
    md5_hashes   = "['009cefb91f050d5191eab81a331f43bb','010e5549fc22b96c1227fc77bbc26814','2c37e31416cfc27770f581a6ff063d89']"

  strings:
    $hex_string = { 83 c4 10 85 db 75 04 31 c0 eb 29 0f b7 43 58 80 7c 30 5c 00 74 13 83 c4 fc 6a 00 56 50 e8 33 ff ff ff 8b 00 eb 05 8d 76 00 8b 06 89 03 8b 43 08 01 03 89 d8 8d 65 e8 5b 5e c9 c3 89 f6 55 89 e5 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}