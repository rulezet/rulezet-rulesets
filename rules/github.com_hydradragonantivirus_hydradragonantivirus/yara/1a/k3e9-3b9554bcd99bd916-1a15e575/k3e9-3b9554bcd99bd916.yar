rule k3e9_3b9554bcd99bd916 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e9.3b9554bcd99bd916"
    cluster      = "k3e9.3b9554bcd99bd916"
    cluster_size = "4"
    filetype     = "PE32 executable (GUI) Intel 80386"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171121"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "backdoor cossta farfli"
    md5_hashes   = "['a4f111deb4a806904f44218ce6ea5ef6','b859cdf0e6d96b6c2a6785a1ac454ac3','e95703844693eb17b3b079085f64d5e9']"

  strings:
    $hex_string = { 95 6f f1 57 38 8f 65 ae 3d c2 39 b9 7c e6 fc 98 60 29 b3 b5 45 75 dc 21 e7 99 d2 2c 58 bf 2a a3 a3 14 fa fd 04 72 24 70 1d f5 64 5d 6a e6 71 e4 47 a9 41 ff 4a f6 cf 85 7e 6e 73 15 ce a8 09 18 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}