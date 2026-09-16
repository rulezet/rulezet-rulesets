rule o3ec_0050ab41d9abd111 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=o3ec.0050ab41d9abd111"
    cluster      = "o3ec.0050ab41d9abd111"
    cluster_size = "1035"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "virut virtob sality"
    md5_hashes   = "['001c9e94133abfd8fbcc7c28849bf3d6','00506d62100e6aa14bd28bd7c270112f','0594add9f3985c13b5c6bfca0d5672b9']"

  strings:
    $hex_string = { 5e 32 27 33 08 34 dd 34 c1 35 a8 36 8f 37 76 38 5d 39 46 3a 25 3b 04 3c e3 3c c2 3d a1 3e 80 3f 00 60 2a 00 2c 00 00 00 5f 30 41 31 31 32 18 33 ff 33 e6 34 cd 35 b4 36 9b 37 84 38 63 39 42 3a }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}