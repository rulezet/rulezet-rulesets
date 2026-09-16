rule k3e9_14de6a08c0000b12 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e9.14de6a08c0000b12"
    cluster      = "k3e9.14de6a08c0000b12"
    cluster_size = "566"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171109"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "bublik generickd upatre"
    md5_hashes   = "['000ba3b3a77a2d970823815ae8387a0b','0228367e4dd27bea96ec34229e4b6d9f','1bf7d54d228274997b6091c91ade5498']"

  strings:
    $hex_string = { 05 52 b4 66 bc 7a 8d 18 10 0e 18 04 e5 eb aa b8 08 27 e5 e8 88 36 31 dc 11 f0 ee ac 71 bc 35 21 f0 65 06 8f d8 ed b1 ce 49 ce 1c 08 16 5f 8e c2 7d 0e b1 0c e2 cd 00 41 bc 5d c9 ea fc b8 5c e2 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}