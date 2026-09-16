rule k3e7_631a29bcca210912 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e7.631a29bcca210912"
    cluster      = "k3e7.631a29bcca210912"
    cluster_size = "10"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171122"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "regrun ludbaruma malicious"
    md5_hashes   = "['dca8b6a6088d9f2b17ffa0bbba5d45ca','dca8b6a6088d9f2b17ffa0bbba5d45ca','dca8b6a6088d9f2b17ffa0bbba5d45ca']"

  strings:
    $hex_string = { 8d 34 e5 8c 30 e4 8a 2d e4 87 29 e3 85 26 e2 82 21 e2 80 1f e1 7d 1c df 79 18 de 76 15 dd 73 14 dc 70 11 db 6d 0f da 6a 0d d9 68 0b d8 65 08 d8 62 08 d7 60 07 d6 5e 06 d5 5c 05 d3 59 04 d1 57 }

  condition:
    filesize > 262144 and filesize < 1048576
    and $hex_string
}