rule o3f1_111354c397d30912 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=o3f1.111354c397d30912"
    cluster      = "o3f1.111354c397d30912"
    cluster_size = "3"
    filetype     = "application/zip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171123"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "triada androidos generickd"
    md5_hashes   = "['32cb69cad3e7ae37d084776bb2e6de5c','4cb9c9d76db6add0e49f488e6dade49f','74243d801e26fee5e016272be8bd0592']"

  strings:
    $hex_string = { 48 1c 25 ee a2 a4 32 99 68 8a 14 8d 46 23 0a 2e 09 51 19 b5 91 f3 34 ae 36 9a a5 fa 26 b9 3d 2c e7 fd d2 b6 4f 1e 9d dd 03 b1 ce cf be 47 a1 5d dc cd b8 c2 e6 38 a7 4a ff 00 12 d3 65 85 98 a8 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}