rule n3f8_6ae30d46dee31114 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=n3f8.6ae30d46dee31114"
    cluster         = "n3f8.6ae30d46dee31114"
    cluster_size    = "14"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180911"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "androidos smforw smsagent"
    md5_hashes      = "['3aa0e5678a3ea1a9b453125f952f7498af9b27d6','88251f6d5223fbfa158a927f6cd80f6e1b1df2c7','93820a895f2a56ea8032d19a4248c1eedd722d58']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=n3f8.6ae30d46dee31114"

  strings:
    $hex_string = { 79 63 6f 6d 62 4d 52 32 53 74 75 62 3b 00 02 3e 28 00 07 3c 54 54 3b 3e 3b 29 00 2e 4c 61 6e 64 72 6f 69 64 2f 73 75 70 70 6f 72 74 2f 76 34 2f 76 69 65 77 2f 56 69 65 77 50 61 67 65 72 24 53 }

  condition:
    filesize > 262144 and filesize < 1048576
    and $hex_string
}