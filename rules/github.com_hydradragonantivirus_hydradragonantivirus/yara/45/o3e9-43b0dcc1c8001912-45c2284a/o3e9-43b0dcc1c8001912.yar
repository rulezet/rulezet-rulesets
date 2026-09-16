rule o3e9_43b0dcc1c8001912 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=o3e9.43b0dcc1c8001912"
    cluster      = "o3e9.43b0dcc1c8001912"
    cluster_size = "18"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "otwycal viking wapomi"
    md5_hashes   = "['0a6cd825af0e1bb50d10a9ccad41e8f4','3975e3ad533d2883f8df984ef6aa997e','d62d91d0a5e6d5201607a5f599995dc5']"

  strings:
    $hex_string = { 12 b7 17 d1 36 35 ca 8a d7 20 9d 0f 9c 4d 7d 71 09 e5 21 38 4e 4c 0c 24 01 d4 52 51 c8 04 b9 e9 d3 2d 15 d8 9f 56 47 84 68 6a 1d 9b 31 a1 7e 37 03 99 5c b4 46 76 80 83 ec 94 1e c6 a9 f4 b5 aa }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}