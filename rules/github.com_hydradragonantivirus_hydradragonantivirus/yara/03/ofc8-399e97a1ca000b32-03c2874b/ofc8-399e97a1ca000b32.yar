rule ofc8_399e97a1ca000b32 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=ofc8.399e97a1ca000b32"
    cluster         = "ofc8.399e97a1ca000b32"
    cluster_size    = "101"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180909"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "riskware rogueurl gphji"
    md5_hashes      = "['f2d6544a02e960a9eda75bc915c926552e1b0c62','86541f6bfdef9bc5728b587764cbf728a25787a9','eadbd7b55b0c31eb1579e21d26d1b30e7d3d8d53']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=ofc8.399e97a1ca000b32"

  strings:
    $hex_string = { b1 05 c8 5e b8 12 30 85 54 86 71 5b 9c 1d 4a d5 da d7 28 80 ab ad 91 60 dd 13 b0 6a 2e e3 74 9a 37 45 10 35 f7 c4 4e 50 64 29 0c 7b 4d c5 58 8a 56 6e 08 3f 67 db ac 22 eb e1 61 3c 2b 2a e6 39 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}