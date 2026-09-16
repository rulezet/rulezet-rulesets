rule k3e9_42be0702c496464e {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e9.42be0702c496464e"
    cluster      = "k3e9.42be0702c496464e"
    cluster_size = "423"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "virut virtob virux"
    md5_hashes   = "['003e233c5d2d3e7d5021eb3878f596ab','0257dc49e01e9addad02b60772c8cd79','09c29793ca206c6dd72f4b47ee8d6047']"

  strings:
    $hex_string = { 43 3b 3b 3d 3f 31 2d 49 3a 2b 24 54 3a 2b 26 65 3d 2f 2d 7d 3c 2f 2b 94 39 27 22 a5 44 3f 41 bc 5b 6d 7e d8 54 6c a2 ea 61 88 c7 f6 62 89 c6 f8 63 8b c7 f8 49 4a 5a e3 38 25 1f c0 38 29 26 95 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}