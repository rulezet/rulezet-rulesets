rule k26df_4a2111649e830080 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=k26df.4a2111649e830080"
    cluster         = "k26df.4a2111649e830080"
    cluster_size    = "1857"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "nsis adload swbundler"
    md5_hashes      = "['c090ef5a0f70692611be5f220b28b5c992b6021e','e3a9c1a24202195aae0e92f91734d9b33e0da158','845a18b9b35c5d711c360d1f7cdbfefe88c41b81']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=k26df.4a2111649e830080"

  strings:
    $hex_string = { e0 30 80 2c 00 01 e0 32 80 2c 00 01 e0 33 80 2c 00 72 00 6f 00 00 00 41 00 42 00 43 00 44 00 45 00 46 00 47 00 48 00 49 00 4a 00 4b 00 4c 00 4d 00 4e 00 4f 00 50 00 51 00 52 00 53 00 54 00 55 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}