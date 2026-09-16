rule k3e9_09346de159b2e316 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e9.09346de159b2e316"
    cluster      = "k3e9.09346de159b2e316"
    cluster_size = "41"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "installcore unwanted browsefox"
    md5_hashes   = "['045ffb8bf0a75cd6a232361b4ad1393d','1a5edf7b5a2d6a3a4354f3a4b19dd97e','7e758f54d763b50ae209caf929d459be']"

  strings:
    $hex_string = { 50 77 a4 a0 ce 51 03 55 ff 0e d7 68 a6 17 55 6e 29 c4 b4 ce ea a1 76 a9 4f 00 1d 13 32 7f ef f9 8e ae 8c 39 bf 2b ef 69 59 59 1b 11 13 9e 23 c6 9b c7 19 21 bc 22 e8 0c df 72 f1 4b 99 73 e4 d5 }

  condition:
    filesize > 262144 and filesize < 1048576
    and $hex_string
}