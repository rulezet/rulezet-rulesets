rule n3fa_211d8b8bcee31932 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=n3fa.211d8b8bcee31932"
    cluster      = "n3fa.211d8b8bcee31932"
    cluster_size = "6261"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171109"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "snare snarasite adsnare"
    md5_hashes   = "['000302cbd5bac128d6446984c2c507b4','00086883f12db4591ed740caecae8b2e','00b981235eacfb285da13e895f5c99d1']"

  strings:
    $hex_string = { 2b 92 fe f1 55 e6 03 4c 88 14 38 36 e7 a0 c3 b7 39 b8 bd 13 3f ff aa 9c 86 03 78 7f 9c 3c 41 3c 64 c6 6d c7 ac e7 26 2d c9 a5 e1 48 fb 79 89 dc c0 1d 88 b9 bb c6 a7 51 77 ac f9 56 c5 f6 60 8e }

  condition:
    filesize > 262144 and filesize < 1048576
    and $hex_string
}