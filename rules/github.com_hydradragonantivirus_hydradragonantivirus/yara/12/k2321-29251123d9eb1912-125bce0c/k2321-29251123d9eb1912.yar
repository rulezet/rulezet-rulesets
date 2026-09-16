rule k2321_29251123d9eb1912 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k2321.29251123d9eb1912"
    cluster      = "k2321.29251123d9eb1912"
    cluster_size = "4"
    filetype     = "application/gzip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "vobfus symmi vbkrypt"
    md5_hashes   = "['180c019020bdf5cf746908caad25e934','7f1a5bd3ddf7c85504612cd929aae2a3','8fa82d3a29bce5fa6cb1cfe61e18ad78']"

  strings:
    $hex_string = { a6 c4 d9 5d ae 44 1f 1d 03 05 b3 60 40 9d af b2 3f f1 93 33 ab a0 0b 36 1b 9d 0f ba 0a 79 56 6c 09 8f 5a 39 6b ff d1 b8 4e 4a c9 3a 2e 7a 8e 35 68 c5 c8 45 a2 e3 4b dc cc f6 df 4c 65 ec c3 d8 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}