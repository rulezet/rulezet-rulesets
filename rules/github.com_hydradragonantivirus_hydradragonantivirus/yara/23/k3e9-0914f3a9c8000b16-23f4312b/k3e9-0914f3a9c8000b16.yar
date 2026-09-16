rule k3e9_0914f3a9c8000b16 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e9.0914f3a9c8000b16"
    cluster      = "k3e9.0914f3a9c8000b16"
    cluster_size = "125"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171117"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "backdoor razy injector"
    md5_hashes   = "['01e8ebd45f8652024d2a2fc6e3288c82','056f317fc1ebaec4fb7a6a6baa153e1a','5d3eac367db43ff4f55ea00e6b846696']"

  strings:
    $hex_string = { 47 01 8a 46 02 88 47 02 8b 45 08 5e 5f c9 c3 90 8d 74 31 fc 8d 7c 39 fc f7 c7 03 00 00 00 75 24 c1 e9 02 83 e2 03 83 f9 08 72 0d fd f3 a5 fc ff 24 95 30 68 40 00 8b ff f7 d9 ff 24 8d e0 67 40 }

  condition:
    filesize > 65536 and filesize < 262144
    and $hex_string
}