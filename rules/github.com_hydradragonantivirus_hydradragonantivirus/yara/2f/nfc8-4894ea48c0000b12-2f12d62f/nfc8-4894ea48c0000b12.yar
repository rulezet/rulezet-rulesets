rule nfc8_4894ea48c0000b12 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=nfc8.4894ea48c0000b12"
    cluster         = "nfc8.4894ea48c0000b12"
    cluster_size    = "7"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180911"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "banker androidos svpeng"
    md5_hashes      = "['fbeced54975b53f6aa2ef67ee2e4aaca5d38106d','25981f456063725091c49208824a795444999c0c','50298d78e4dcf92ddea018ef46460cbd4a404ca6']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=nfc8.4894ea48c0000b12"

  strings:
    $hex_string = { b7 b4 a8 46 79 37 c0 68 0a 7b 22 fd f0 a3 57 43 5a 00 f1 18 ac 0c 85 47 d6 0e 7a 2f b8 f9 9c a1 32 6a 74 5c 6b 9d 16 72 c7 ef 43 af bf 3b bc 9f 05 7e e2 bd 02 ab 53 89 db f7 97 1b 36 03 50 de }

  condition:
    filesize > 262144 and filesize < 1048576
    and $hex_string
}