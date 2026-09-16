rule k3e9_0919f3a9c8000b12 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e9.0919f3a9c8000b12"
    cluster      = "k3e9.0919f3a9c8000b12"
    cluster_size = "31"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171117"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "backdoor tofsee injector"
    md5_hashes   = "['18ac87d459dde36030788bd5c2de85d4','2bef3716e320fccef0aa8541b23ab6d0','ba711f1b2274a8f61e71cd843d0dc9b3']"

  strings:
    $hex_string = { 88 47 01 8a 46 02 88 47 02 8b 45 08 5e 5f c9 c3 90 8d 74 31 fc 8d 7c 39 fc f7 c7 03 00 00 00 75 24 c1 e9 02 83 e2 03 83 f9 08 72 0d fd f3 a5 fc ff 24 95 30 68 40 00 8b ff f7 d9 ff 24 8d e0 67 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}