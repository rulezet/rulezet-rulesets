rule i3ed_291f5b4f2ba10b12 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=i3ed.291f5b4f2ba10b12"
    cluster      = "i3ed.291f5b4f2ba10b12"
    cluster_size = "90"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "debris gamarue zusy"
    md5_hashes   = "['05b5ee87ed947c1fb4dfc0526c44f96c','0626016f1122e7328946d4fea150a66f','3d7631ed38275552ef4e13907f06788a']"

  strings:
    $hex_string = { 85 c0 74 0f 8b 4d 08 8a 11 80 c2 01 8b 45 08 88 10 eb de 5d c3 cc cc cc cc cc cc cc cc cc cc cc 55 8b ec 51 8b 45 0c 89 45 fc 83 7d fc 01 74 02 eb 0d 68 00 30 00 10 e8 a4 ff ff ff 83 c4 04 b8 }

  condition:
    filesize > 1024 and filesize < 4096
    and $hex_string
}