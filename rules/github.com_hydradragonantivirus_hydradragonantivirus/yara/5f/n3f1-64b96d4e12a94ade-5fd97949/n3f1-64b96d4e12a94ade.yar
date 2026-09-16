rule n3f1_64b96d4e12a94ade {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=n3f1.64b96d4e12a94ade"
    cluster      = "n3f1.64b96d4e12a94ade"
    cluster_size = "40"
    filetype     = "application/zip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171123"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "androidos gudex revo"
    md5_hashes   = "['02155126af475e96c956aabd0ebccaac','053b51f6feb94568590b3ce5ca84469c','77b891f3c50ee18307f7cb96ac22748e']"

  strings:
    $hex_string = { b1 00 72 71 38 f9 36 2f ce 05 22 97 89 b7 5b 8d 88 a9 63 55 f4 a5 29 e4 46 e8 4c a6 e6 6a 46 e7 3c c9 70 12 0c d2 de 17 49 d3 0e f8 e3 11 35 bf 57 4f fa 47 d7 0b 9f 94 4e e2 b3 be 58 19 10 92 }

  condition:
    filesize > 262144 and filesize < 1048576
    and $hex_string
}