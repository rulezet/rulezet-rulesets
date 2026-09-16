rule o26bb_33bd1149c0000b12 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=o26bb.33bd1149c0000b12"
    cluster         = "o26bb.33bd1149c0000b12"
    cluster_size    = "3616"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180909"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "symmi malicious hacktool"
    md5_hashes      = "['b2b09bf201e1d43952d55f687a721bc3dfe7b595','48c343b76119946c7a19b57950542a2c3eaaad0b','ef673fee5f29b3f9bc43f5c23ec77836ed6d969e']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=o26bb.33bd1149c0000b12"

  strings:
    $hex_string = { 24 06 c3 0f e8 2e 7f ff ff eb 01 b0 85 c0 0f 84 2c 00 00 00 f8 73 01 b7 f9 72 01 bd 51 56 57 9c fc 33 f6 87 75 08 8b 7d 0c 8b 3f 8b 07 40 6b c0 04 03 f8 8b 4d 10 66 f3 a5 ff 45 08 9d 5f 5e 59 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}