rule o3f8_6a1f2954c6830b12 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=o3f8.6a1f2954c6830b12"
    cluster         = "o3f8.6a1f2954c6830b12"
    cluster_size    = "11"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180909"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "androidos ginamster clicker"
    md5_hashes      = "['256fef74b799963bec47af1a513cc811771b1a61','c699188a2ca6f3af342f4fe76f3680e87fd4543f','6460e6a80f44c7f83fca5059061e6f88150bc4c2']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=o3f8.6a1f2954c6830b12"

  strings:
    $hex_string = { 01 60 00 40 60 61 62 63 64 65 66 67 68 69 6a 6b 6c 6d 6e 6f 70 71 72 73 74 75 76 77 78 79 7a ef bf ba 1c 1d 1e ef bf bb 7b ef bf bc 7d 7e 7f 3b 3c 3d 3e 3f 5b 5c 5d 5e 5f 20 2c 2e 2f 3a 40 21 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}