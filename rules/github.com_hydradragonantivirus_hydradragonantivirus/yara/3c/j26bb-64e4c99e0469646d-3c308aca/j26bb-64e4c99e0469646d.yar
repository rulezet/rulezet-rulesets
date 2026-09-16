rule j26bb_64e4c99e0469646d {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=j26bb.64e4c99e0469646d"
    cluster         = "j26bb.64e4c99e0469646d"
    cluster_size    = "84"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "poison backdoor bkdr"
    md5_hashes      = "['a5c24d5f6c4f6e160106d78030a06b8e96bae41c','5c114de3ff33abdade3dd05fa3c2d4b30815d61e','9bcaed0113a8c8cee414356628f08b6c751e36f0']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=j26bb.64e4c99e0469646d"

  strings:
    $hex_string = { eb 2b f9 85 d2 75 bf 46 c1 e8 10 88 06 e9 2b 02 00 00 c1 e8 10 83 e2 0f 89 44 24 54 74 2a 3b fa 73 12 0f b6 45 01 45 8b cf d3 e0 89 6c 24 10 03 d8 83 c7 08 8b ca b8 01 00 00 00 d3 e0 48 23 c3 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}