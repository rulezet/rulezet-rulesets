rule j3f4_090ee128c0800b32 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=j3f4.090ee128c0800b32"
    cluster      = "j3f4.090ee128c0800b32"
    cluster_size = "652"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171123"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "razy agbf asvcs"
    md5_hashes   = "['000a1fd3166419daefc52101e1533f0f','002ee20badb5329ebaff003c0b899145','054ea83b952b45a03047d107bcafa38f']"

  strings:
    $hex_string = { ff 96 e8 ff ff 94 e8 ff ff 92 e7 ff ff 91 e7 ff ff 8f e7 ff ff 8e e6 ff ff 8c e6 ff ff 8b e6 ff ff 58 cc ef ff 4f c8 ec ff 47 c4 e9 bf 00 00 00 00 00 00 00 00 00 00 00 00 4a cb ee ff 99 e9 ff }

  condition:
    filesize > 4096 and filesize < 16384
    and $hex_string
}