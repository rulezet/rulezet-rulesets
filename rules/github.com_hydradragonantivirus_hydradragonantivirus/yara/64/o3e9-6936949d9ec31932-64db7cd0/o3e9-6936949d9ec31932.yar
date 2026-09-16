rule o3e9_6936949d9ec31932 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=o3e9.6936949d9ec31932"
    cluster      = "o3e9.6936949d9ec31932"
    cluster_size = "61"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "graftor flooder malicious"
    md5_hashes   = "['0af3d238940e04eab601b5127a6ec847','1124fc0a74efaf1c8a9576326b4ff1f7','6d42b5de20b6a450367fbce5dee892d0']"

  strings:
    $hex_string = { a3 e0 c2 e3 39 1c 5c 10 db 67 1d da b9 e9 dc b2 27 4c f0 9a e7 61 81 cf c4 4d 06 33 6e fb cd 48 00 f6 5d 3d 90 24 7a 80 fd bf 95 04 ab 34 a2 2e 32 ef 18 ca 5f 76 b8 88 9b bd ec f5 4f c8 42 b3 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}