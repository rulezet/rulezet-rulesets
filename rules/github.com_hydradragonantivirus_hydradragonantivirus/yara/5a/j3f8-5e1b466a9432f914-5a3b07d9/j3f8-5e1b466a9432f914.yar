rule j3f8_5e1b466a9432f914 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=j3f8.5e1b466a9432f914"
    cluster         = "j3f8.5e1b466a9432f914"
    cluster_size    = "3"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "androidos jisut boogr"
    md5_hashes      = "['fb14a00e0dfb127a860ae5346434c08fe35729f2','7387da057118066c40c1bf61b12fee39938e05f8','c9fc8df4cf4b49945cc23929304f57ee5a209a7a']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=j3f8.5e1b466a9432f914"

  strings:
    $hex_string = { 61 67 65 72 24 4e 61 6d 65 4e 6f 74 46 6f 75 6e 64 45 78 63 65 70 74 69 6f 6e 3b 00 1a 4c 61 6e 64 72 6f 69 64 2f 6f 73 2f 42 75 69 6c 64 24 56 45 52 53 49 4f 4e 3b 00 07 53 44 4b 5f 49 4e 54 }

  condition:
    filesize > 4096 and filesize < 16384
    and $hex_string
}