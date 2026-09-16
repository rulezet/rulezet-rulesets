rule o3e9_49583ec9c4000912 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=o3e9.49583ec9c4000912"
    cluster      = "o3e9.49583ec9c4000912"
    cluster_size = "4"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171123"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "virlock malicious nabucur"
    md5_hashes   = "['13034b0997c5e9ffce04eb9f2c3d874b','25a676959e895ac4a8e8872759d6c997','beca40d7310248835cc866571b88bfa5']"

  strings:
    $hex_string = { f8 d5 b4 ff f5 d3 b3 ff f3 d0 b2 ff f0 ce b0 ff ee cb af ff ec ca ad ff eb c8 ac ff e8 c6 aa ff e5 c3 a9 ff e3 c1 a7 ff e2 c0 a6 ff e0 be a4 ff dd bb a3 ff da b9 a2 ff de ae 8f c6 df ac 85 14 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}