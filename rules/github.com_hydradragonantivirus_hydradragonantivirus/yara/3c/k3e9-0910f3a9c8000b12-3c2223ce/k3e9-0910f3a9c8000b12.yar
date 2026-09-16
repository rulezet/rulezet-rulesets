rule k3e9_0910f3a9c8000b12 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e9.0910f3a9c8000b12"
    cluster      = "k3e9.0910f3a9c8000b12"
    cluster_size = "5"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "backdoor tofsee injector"
    md5_hashes   = "['a8a7a98a170918e5cda8319b4375d255','bff8996dfc72ffa1bdcd7aa85fa37526','e8f5574b7a65cf7485ffbf32665a6cb2']"

  strings:
    $hex_string = { 8d 49 00 8a 06 88 07 8a 46 01 88 47 01 8a 46 02 88 47 02 8b 45 08 5e 5f c9 c3 90 8d 74 31 fc 8d 7c 39 fc f7 c7 03 00 00 00 75 24 c1 e9 02 83 e2 03 83 f9 08 72 0d fd f3 a5 fc ff 24 95 30 68 40 }

  condition:
    filesize > 65536 and filesize < 262144
    and $hex_string
}