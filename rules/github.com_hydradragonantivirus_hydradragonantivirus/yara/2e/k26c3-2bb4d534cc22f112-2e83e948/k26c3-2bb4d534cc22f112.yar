rule k26c3_2bb4d534cc22f112 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=k26c3.2bb4d534cc22f112"
    cluster         = "k26c3.2bb4d534cc22f112"
    cluster_size    = "109"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "mirai linux backdoor"
    md5_hashes      = "['ea91d757aa4429b24df25622a7a3ec7006843de5','dbe21479e3fc17b74cf530e8a729e08214ab985e','f50b0665b145514aca449b7b50049a990df88bd6']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=k26c3.2bb4d534cc22f112"

  strings:
    $hex_string = { fe b4 40 91 fe 9c 4b ff fe 9c 83 aa 00 10 48 00 3f 99 81 21 00 08 56 94 20 3e 7e 80 11 20 56 94 e0 3e 1d 29 00 18 7d 29 ca 14 88 09 00 14 7c 63 04 30 7f bd 1a 14 93 bc 00 10 40 9e fe b0 3b a0 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}