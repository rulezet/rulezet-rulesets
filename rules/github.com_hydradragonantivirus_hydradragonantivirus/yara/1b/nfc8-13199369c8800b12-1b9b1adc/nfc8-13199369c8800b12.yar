rule nfc8_13199369c8800b12 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=nfc8.13199369c8800b12"
    cluster         = "nfc8.13199369c8800b12"
    cluster_size    = "74"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180911"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "banker androidos origin"
    md5_hashes      = "['2018f5a693f3967bd727a8a43ae5b0e5380e4675','c343f70776d19076e1380e7da818a38cc63ab688','d99fbaa5fd5a3d52caf50f8681f6edacbd8be8b5']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=nfc8.13199369c8800b12"

  strings:
    $hex_string = { 52 de ed d6 ad db 5a 16 8b e5 a7 cd 89 2e e6 fe 0f 31 bc 4d 28 ae 7b 4c 2c f3 4e e7 10 ac 08 5e 0a 57 33 67 62 99 3b 65 77 b1 26 7e 3d ee 94 a5 3e f7 ff 13 ba 8d 43 64 f0 32 30 e8 0c 12 9f a8 }

  condition:
    filesize > 262144 and filesize < 1048576
    and $hex_string
}