rule o3e7_6136848cca210912 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=o3e7.6136848cca210912"
    cluster      = "o3e7.6136848cca210912"
    cluster_size = "5"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171122"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "optimizerpro speedingupmypc riskware"
    md5_hashes   = "['0e7ac65069e956d5a14fc35c51deb259','b182e31de82885942be3ad69de8057c0','e405b506ecdda71d1b831a77438049c3']"

  strings:
    $hex_string = { 7c c8 04 4d 77 fa 50 51 84 37 57 93 fd 64 cb 06 7e 18 78 49 40 a8 00 e6 0f a3 27 cf 4c d2 e8 b0 f5 8e 83 9c b8 61 e9 ac c6 91 a7 4a bc 7d b5 d3 5d 30 0a c5 7b 9b 12 e7 09 cd 85 2f a9 43 ca 41 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}