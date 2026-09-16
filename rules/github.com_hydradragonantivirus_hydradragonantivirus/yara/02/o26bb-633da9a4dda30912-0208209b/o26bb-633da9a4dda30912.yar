rule o26bb_633da9a4dda30912 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=o26bb.633da9a4dda30912"
    cluster         = "o26bb.633da9a4dda30912"
    cluster_size    = "18"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180909"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "bundler malicious adload"
    md5_hashes      = "['e4a81af1722af30747b5c97afc4dacb8623a0863','b74ab614ae5218ff77fdab01e9bd6b41d1c27080','a4c344c1114220971c55e1e80de2e6f525ce3524']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=o26bb.633da9a4dda30912"

  strings:
    $hex_string = { 45 46 47 48 49 4a 4b 4c 4d 4e 4f 50 51 52 53 54 55 56 57 58 59 5a 61 62 63 64 65 66 67 68 69 6a 6b 6c 6d 6e 6f 70 71 72 73 74 75 76 77 78 79 7a 5d 00 00 00 25 30 32 64 3a 25 30 32 64 3a 25 30 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}