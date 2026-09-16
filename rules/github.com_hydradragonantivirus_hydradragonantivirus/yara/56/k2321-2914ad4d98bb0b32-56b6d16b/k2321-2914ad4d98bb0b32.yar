rule k2321_2914ad4d98bb0b32 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k2321.2914ad4d98bb0b32"
    cluster      = "k2321.2914ad4d98bb0b32"
    cluster_size = "6"
    filetype     = "application/gzip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171117"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "zusy emotet tinba"
    md5_hashes   = "['3bf80e4b98d5f7e293212b144511f949','3c6cc2c3a36474886698dd3b899eee6d','dd236614124e0d9f69281e8e0038078c']"

  strings:
    $hex_string = { 57 77 f0 fb 1f b6 6e da 34 7e cc 98 b8 a8 68 9d 42 21 43 12 16 f0 d5 52 69 20 32 85 4a 05 b1 00 49 c8 66 8b 39 1c bd 56 db a7 47 8f 82 99 33 df 7d eb 2d 38 e3 a5 a6 46 48 78 f2 e0 3e e8 76 ff }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}