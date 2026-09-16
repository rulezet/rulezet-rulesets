rule k3e9_193c69e351b2f316 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e9.193c69e351b2f316"
    cluster      = "k3e9.193c69e351b2f316"
    cluster_size = "16"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171118"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "dealply installcore domaiq"
    md5_hashes   = "['22347d20ab1bfca8340b36e60f32cda3','35d6b55daf5e4d5f3da96d163e0d9601','fb1aa1f744bee03078e90462b1d0d207']"

  strings:
    $hex_string = { cf 78 fe 72 12 1d 0f 4f 07 c8 f6 7b 6c a7 c6 7e 8a 02 b4 4b 90 d4 27 fa 99 5c 05 03 62 cb bc f8 00 2b 40 a9 a8 09 db 9f 22 93 53 2a 3f 3c c9 43 84 41 1c 6d 82 36 94 da ec 28 e6 38 49 d6 69 e8 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}