rule n3f8_5a52ea08c0000b30 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=n3f8.5a52ea08c0000b30"
    cluster         = "n3f8.5a52ea08c0000b30"
    cluster_size    = "139"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180911"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "androidos boogr banker"
    md5_hashes      = "['b1e4b8b8dba886687e1be46c0d8c6e216205a3e0','c6e963b7c3918a67e7c489ce8c0c4a60796cf447','f1c23df3bbb7975e08fff4fde96625aab927a4fe']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=n3f8.5a52ea08c0000b30"

  strings:
    $hex_string = { 62 69 6c 69 74 79 45 76 65 6e 74 3b 00 0d 4c 61 73 74 2d 4d 6f 64 69 66 69 65 64 00 1d 4c 63 6f 6d 2f 73 71 75 61 72 65 75 70 2f 6f 6b 68 74 74 70 2f 41 64 64 72 65 73 73 3b 00 23 4c 63 6f 6d }

  condition:
    filesize > 262144 and filesize < 1048576
    and $hex_string
}