rule o3e9_365128c696536b9a {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=o3e9.365128c696536b9a"
    cluster      = "o3e9.365128c696536b9a"
    cluster_size = "579"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171109"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "installmonster installmonstr malicious"
    md5_hashes   = "['006446673a5c89e1c6fcd52981c10a41','015d2e3b88050ab9070647ed2b9fa14b','08ee7f359c72fb651ec2c684006cb830']"

  strings:
    $hex_string = { d2 bb fd c7 8c ba 00 12 38 d7 b6 a1 0d 7e ea aa 0f 0f 68 b7 43 7a 83 03 44 f3 b8 71 18 10 6c d2 7d 69 bd 6f 51 3e d9 2f 08 f7 dc 31 17 c4 86 ef 74 bf be c0 83 fa 44 ae a0 22 ce 93 af cf 0d 68 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}