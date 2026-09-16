rule n3f8_6d38c209c6200b32 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=n3f8.6d38c209c6200b32"
    cluster         = "n3f8.6d38c209c6200b32"
    cluster_size    = "618"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "androidos backdoor banker"
    md5_hashes      = "['898d9d1fbadb32c6b3d6e5097bf195835a93a358','f3e9b6b178808955349319a38c5e14da012935f8','860dcaa4cfd9931016b3c4410fc6afa90e383a27']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=n3f8.6d38c209c6200b32"

  strings:
    $hex_string = { 00 40 30 31 32 33 34 35 36 37 38 39 41 42 43 44 45 46 47 48 49 4a 4b 4c 4d 4e 4f 50 51 52 53 54 55 56 57 58 59 5a 61 62 63 64 65 66 67 68 69 6a 6b 6c 6d 6e 6f 70 71 72 73 74 75 76 77 78 79 7a }

  condition:
    filesize > 262144 and filesize < 1048576
    and $hex_string
}