rule o3e9_0b1359b65852e392 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=o3e9.0b1359b65852e392"
    cluster      = "o3e9.0b1359b65852e392"
    cluster_size = "256"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171109"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "dlboost installmonster installmonstr"
    md5_hashes   = "['0080f8d5881513a682ae2c143fc1031a','00abf5ae6a859215bc2ab16d716c5731','0c9f05d60b486abef2a3652347ea3a13']"

  strings:
    $hex_string = { 3d dd fb ae 53 fa b2 a6 a2 30 8e c8 f8 07 7c b8 1b df 5e 06 54 46 7d 60 2c e1 e2 dd e1 5c 9a 26 b3 b3 30 42 b3 ac 7f 5a b7 bd dc 08 ad ec 6e f2 ac 8f a4 d7 a6 63 12 c3 37 0d 4b cf fb fa 6a d7 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}