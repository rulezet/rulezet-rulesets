rule j2328_2ba6b6469e9b0b12 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=j2328.2ba6b6469e9b0b12"
    cluster         = "j2328.2ba6b6469e9b0b12"
    cluster_size    = "306"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "script exploit html"
    md5_hashes      = "['9723d8a4b53bd94db320cce8c92992bb5d4e7d8c','3b2492f2926032fb93db6d91027ae1520fc5f053','629268bf51818383619161d8d7661cb76f5b1de7']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=j2328.2ba6b6469e9b0b12"

  strings:
    $hex_string = { e7 ac ac 33 37 e5 b1 86 e6 a0 a1 e9 9a 9b e8 88 9e e8 b9 88 e6 af 94 e8 b3 bd 3c 2f 74 69 74 6c 65 3e 0a 20 20 20 20 20 20 3c 6c 69 6e 6b 3e 68 74 74 70 3a 2f 2f 65 6d 6d 70 64 2e 65 64 75 2e }

  condition:
    filesize > 4096 and filesize < 16384
    and $hex_string
}