rule k2318_1719a6b9c8800b12 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=k2318.1719a6b9c8800b12"
    cluster         = "k2318.1719a6b9c8800b12"
    cluster_size    = "25"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "iframe redirector html"
    md5_hashes      = "['1df624ba1db071b7a2eacfb1e2679498f7753d83','af4de88c9ad34deeebe0ae649b18eb3c8384d869','32d7f0d31e6116f8a0d0b9283393c4a4e849d987']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=k2318.1719a6b9c8800b12"

  strings:
    $hex_string = { 69 7a 65 3d 22 31 22 20 73 74 79 6c 65 3d 22 77 69 64 74 68 3a 20 31 30 30 25 22 3e 3c 6f 70 74 69 6f 6e 20 76 61 6c 75 65 3d 22 22 20 53 45 4c 45 43 54 45 44 3e c2 fb e1 e5 f0 e8 f2 e5 3c 2f }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}