rule k26bb_4934f18997eb9916 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=k26bb.4934f18997eb9916"
    cluster         = "k26bb.4934f18997eb9916"
    cluster_size    = "10"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "malicious virut susp"
    md5_hashes      = "['78b51bb8b01eaf8352dab36f675202c07d401dfa','051896b8f25a232eba1da6afb911c147a3cb7548','d582ec18a99cbf7855ed93f3bbd504612f974626']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=k26bb.4934f18997eb9916"

  strings:
    $hex_string = { 12 f6 85 3c 74 e6 af d6 47 b5 fa f0 ca 90 d7 43 64 68 ce 92 a7 32 70 60 4c 8d 05 25 84 0b b8 66 03 c4 27 78 5c 81 73 6f 49 94 63 1a 15 22 eb 7f 04 61 2c 8d bb c0 6a 50 48 bc 0f b1 c2 1b 41 82 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}