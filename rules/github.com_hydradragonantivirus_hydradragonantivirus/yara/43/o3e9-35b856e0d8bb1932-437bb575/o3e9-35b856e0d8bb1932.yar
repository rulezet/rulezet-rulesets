rule o3e9_35b856e0d8bb1932 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=o3e9.35b856e0d8bb1932"
    cluster      = "o3e9.35b856e0d8bb1932"
    cluster_size = "6"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "cosmu mikey malicious"
    md5_hashes   = "['1666ee500dc7fcf1cc250e9c66a32a04','17302b4e2cef1ac4dae260254bdebb72','e1f04496adffa0af744426177c77f384']"

  strings:
    $hex_string = { ff 9d 55 34 64 19 ab 84 a6 9e 98 74 d7 16 37 94 f0 b0 ec a2 08 25 93 e9 56 d6 30 f8 dd 40 7e 5e d5 91 69 36 17 87 b4 ba 35 4f 71 e2 b3 f9 af dc 12 a8 1d 20 04 bb 45 9c 26 2c 8b 86 1b cf 3a 5f }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}