rule j3e9_131257d2c92bdb32 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=j3e9.131257d2c92bdb32"
    cluster      = "j3e9.131257d2c92bdb32"
    cluster_size = "4"
    filetype     = "PE32 executable (GUI) Intel 80386"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171124"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "upatre bublik generickd"
    md5_hashes   = "['19e8e6ad45b3ea92becc7e8e06140849','20bc72bb1c81a8afa2a8cd7b35402f60','4619fa8791404a8fda97af15a4917455']"

  strings:
    $hex_string = { b3 48 d7 90 64 f0 57 0f a4 7e 92 1f 7f 0b 8f 88 51 fc da 8c c1 8b 10 d2 c4 2f ef 08 23 fd 46 75 8e d1 34 36 5f 67 6a fe 6e 0d 3d 22 72 f2 d5 59 42 78 96 4e 33 65 9c 2e 9b 70 8f cf d5 9a bf f9 }

  condition:
    filesize > 4096 and filesize < 16384
    and $hex_string
}