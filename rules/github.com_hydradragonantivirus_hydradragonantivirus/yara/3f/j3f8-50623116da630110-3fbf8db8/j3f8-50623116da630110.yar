rule j3f8_50623116da630110 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=j3f8.50623116da630110"
    cluster         = "j3f8.50623116da630110"
    cluster_size    = "29"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "lockscreen locker androidos"
    md5_hashes      = "['86b2214b1aef9ac92aa3220e4424f55278f8adc6','6caeeb15bcd943ca8bd267219097cd37a01aa530','82294b97270547e077951bc4ea2bbdd7a494fdee']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=j3f8.50623116da630110"

  strings:
    $hex_string = { 05 7f 6e 20 18 00 76 00 0c 06 1f 06 17 00 07 62 07 26 22 07 1f 00 07 7d 07 d7 07 d8 07 09 70 20 2c 00 98 00 6e 20 1c 00 76 00 22 06 15 00 07 6d 07 d6 07 d7 12 e8 12 e9 13 0a d2 07 12 1b 12 dc }

  condition:
    filesize > 4096 and filesize < 16384
    and $hex_string
}