rule o26d4_694692c9cc000b32 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=o26d4.694692c9cc000b32"
    cluster         = "o26d4.694692c9cc000b32"
    cluster_size    = "82"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180909"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "razy gamehack malicious"
    md5_hashes      = "['e5650ef39383c44655bd72dd162dfedc92f485bd','4bc5c04478831b5527979ef851da4c9d623b4781','b85d51f840496d73b27624479e0c160c782d1dae']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=o26d4.694692c9cc000b32"

  strings:
    $hex_string = { bd 00 58 97 bd 00 a0 9d 3c 00 a0 9d 3c 00 44 01 3e 00 44 01 3e 00 d8 9f 3d 00 d8 9f 3d 00 c0 c5 bc 00 c0 c5 bc 00 40 a2 bd 00 40 a2 bd 00 20 1e be 00 20 1e be 00 60 3f be 00 60 3f be 00 f0 e7 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}