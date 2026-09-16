rule n3f8_2a146ea5ece10b12 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=n3f8.2a146ea5ece10b12"
    cluster         = "n3f8.2a146ea5ece10b12"
    cluster_size    = "5"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "styricka androidos apprisk"
    md5_hashes      = "['a716adb55fcb32e805eed4356e7807565b650a8d','9459dcca5f95bfc90b033cf9918e76dac9378354','eb3b0757808a9e556915f0d15a5b59080db3a10b']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=n3f8.2a146ea5ece10b12"

  strings:
    $hex_string = { 9a e7 ba bf e7 a8 8b e6 93 8d e4 bd 9c 49 6d 70 6c 2e 6a 61 76 61 00 04 e5 a4 9a e8 a1 8c e8 be 93 e5 85 a5 00 05 e5 a4 9a e9 80 89 e5 af b9 e8 af 9d e6 a1 86 00 04 e5 a4 a7 e6 95 b0 e6 af 94 }

  condition:
    filesize > 262144 and filesize < 1048576
    and $hex_string
}