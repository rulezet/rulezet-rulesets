rule o26c0_2335a10499eb1916 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=o26c0.2335a10499eb1916"
    cluster         = "o26c0.2335a10499eb1916"
    cluster_size    = "11"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180909"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "razy gamehack injector"
    md5_hashes      = "['4d90c4ddba3d76f7e9f002feaaa42be77023e0e1','afb40aad18dd52945dcbfad4b4c1937691bdef36','17ce1e0c5ad75fc2d13a18e0f53c3062727dbdf1']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=o26c0.2335a10499eb1916"

  strings:
    $hex_string = { 58 05 90 99 0c 10 8b 45 08 0f 2f 40 20 76 72 8d 4d f0 e8 c7 68 ff ff 8d 4d f0 51 69 55 0c e8 03 00 00 6b 45 fc 28 8d 8c 02 34 88 10 10 51 e8 7b 0e 09 00 83 c4 08 0f b6 d0 85 d2 74 44 68 50 d0 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}