rule k26c3_2b9291ebce220b16 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=k26c3.2b9291ebce220b16"
    cluster         = "k26c3.2b9291ebce220b16"
    cluster_size    = "15"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "linux mirai backdoor"
    md5_hashes      = "['a2723452d11eb46eee0fedd5046aeb0c5f298539','096a2414969312fa4d25d70ac654f4defd312af3','1a0ff1a7e17207989e4df0fc70b5022a7579851c']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=k26c3.2b9291ebce220b16"

  strings:
    $hex_string = { e6 39 db 3a 45 d3 cb 36 0f 50 de 92 2d f7 64 d5 84 6f f0 7d 5c 91 98 f6 48 20 7b ec cd da c5 ee 3b 6d 16 a1 9a bb b4 fc ce da e1 24 31 8a 93 5a 3c b0 61 33 ef 44 5e ca 0d 99 85 30 d6 d0 ba 8f }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}