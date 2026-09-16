rule k2321_0935a42dda9af936 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k2321.0935a42dda9af936"
    cluster      = "k2321.0935a42dda9af936"
    cluster_size = "42"
    filetype     = "gzip compressed data"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "nimnul vjadtre wapomi"
    md5_hashes   = "['057b7b1246f00f53ea25b1891c20c151','0742ab1c782d6932d7a824e9d5b75323','5087652ff0441572433cdb3f3bc30196']"

  strings:
    $hex_string = { 4f a3 ff 16 c9 6c 43 d7 31 84 76 99 f3 ad 87 fe 34 39 c5 4e 4f 6b 8d 64 b7 cb 4c 37 e9 9b c0 59 a9 f5 4d cc f6 04 7c e0 c6 f7 6b 41 3e 62 de 9d fc 29 af df 5f 2a 60 ca 9a 26 cd 38 73 3b c3 ef }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}