rule o26bb_5b90d9a294bb1916 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=o26bb.5b90d9a294bb1916"
    cluster         = "o26bb.5b90d9a294bb1916"
    cluster_size    = "33"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180909"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "mikey ardamax keylogger"
    md5_hashes      = "['730adcf320ee4e88867f3d5f8a49da365041e825','c4904559bef5330db238ecfd23fdc0999deb28ac','590b5cd05ceaf40f33ee78785962bb3e6f3767a8']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=o26bb.5b90d9a294bb1916"

  strings:
    $hex_string = { 0f c9 3b 00 80 40 c0 20 a0 60 e0 10 90 50 d0 30 b0 70 f0 08 88 48 c8 28 a8 68 e8 18 98 58 d8 38 b8 78 f8 04 84 44 c4 24 a4 64 e4 14 94 54 d4 34 b4 74 f4 0c 8c 4c cc 2c ac 6c ec 1c 9c 5c dc 3c }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}