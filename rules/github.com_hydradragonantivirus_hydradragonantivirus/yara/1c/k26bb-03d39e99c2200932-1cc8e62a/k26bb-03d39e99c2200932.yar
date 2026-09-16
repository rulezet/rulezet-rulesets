rule k26bb_03d39e99c2200932 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=k26bb.03d39e99c2200932"
    cluster         = "k26bb.03d39e99c2200932"
    cluster_size    = "39"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "browsefox unwanted yontoo"
    md5_hashes      = "['0ef40502ca66112b787b2eafc55454735526018b','2c87d73f8850c858e5fe697922534e6a3d0c4aa4','ae730bfbbe2d14e590a2b10ee8ea2e6455ef571e']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=k26bb.03d39e99c2200932"

  strings:
    $hex_string = { 41 c5 13 0d 3b f3 76 00 64 f2 df bd 9c f1 e9 23 7e 86 99 1a 90 ce 5b b0 94 b9 4b c6 f4 e2 03 34 bc d7 44 6c cc 52 b7 95 ba 21 0c 7f de 5d 27 f1 fc 62 70 82 98 87 16 46 38 42 e1 51 dd 73 7a 2d }

  condition:
    filesize > 262144 and filesize < 1048576
    and $hex_string
}