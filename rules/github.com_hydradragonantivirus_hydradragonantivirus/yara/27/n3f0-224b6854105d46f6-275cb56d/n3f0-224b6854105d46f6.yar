rule n3f0_224b6854105d46f6 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=n3f0.224b6854105d46f6"
    cluster      = "n3f0.224b6854105d46f6"
    cluster_size = "6"
    filetype     = ""
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171111"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "mira uymi icgh"
    md5_hashes   = "['252e4ca9fcdf754c405a120b5a414ae3','346cf06b3d979f25de6b0d745187615e','f1a43e475bd99dba9aa2cb5c5156e938']"

  strings:
    $hex_string = { 3d c5 5d 3b 8b 9e 92 5a 0d 65 17 0c 75 81 86 75 76 c9 48 4d 65 cc c6 91 0e a6 ae a0 19 e3 a3 46 bc dd 8d de f9 9d fb eb 7e aa 51 43 6f c6 df 8c e9 80 c9 47 ba 93 a8 41 bf 3c d5 a6 cf ff 49 1f }

  condition:
    filesize > 262144 and filesize < 1048576
    and $hex_string
}