rule k3e9_6a92599c1613f111 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e9.6a92599c1613f111"
    cluster      = "k3e9.6a92599c1613f111"
    cluster_size = "2976"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171122"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "gamevance gkdhu adwareare"
    md5_hashes   = "['00023396a0d596c66093b9018960b122','0003b77217a408460226a572cbe2bf75','0118c992ec0576a3d30f94a75a8c5a80']"

  strings:
    $hex_string = { 6e dd 42 e7 2f 2a 07 67 e6 9e 15 49 b9 55 c1 1a 2e e9 d9 d4 72 06 09 a2 88 69 1c fc db c9 b2 93 17 9c ce 30 14 f8 d7 3a 10 45 de 8b 02 6a ac 0d cc 50 7d 0b 7c ff bb 19 ec 8e f5 60 44 b1 73 96 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}