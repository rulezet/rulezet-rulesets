rule n3f1_31c37a84ca230912 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=n3f1.31c37a84ca230912"
    cluster      = "n3f1.31c37a84ca230912"
    cluster_size = "407"
    filetype     = "application/zip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171122"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "androidos andr smsreg"
    md5_hashes   = "['002be9069f0a16e161752b20c6fec48a','00395b545109d65ac0fc9fd6ca4af51e','07fd8796f008eee81637caccaa272bfe']"

  strings:
    $hex_string = { 76 90 72 94 c8 69 17 e4 b4 31 cc c1 9c 36 e6 74 88 6f 4b bd 3d fc 8a 18 c5 10 2e f6 64 82 8b a9 2a 61 35 ad 84 ae cf 6a 48 83 44 c7 55 50 37 dc a5 96 21 d6 a2 2c 59 af 91 78 58 12 0f 2b f5 d9 }

  condition:
    filesize > 262144 and filesize < 1048576
    and $hex_string
}