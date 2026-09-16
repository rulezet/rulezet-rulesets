rule k3e9_193e79e351b2f316 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e9.193e79e351b2f316"
    cluster      = "k3e9.193e79e351b2f316"
    cluster_size = "948"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171122"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "installcore unwanted buzf"
    md5_hashes   = "['0016f783c2324f0e54e956e857fff236','004452b847b408b124369c606591687f','036ae899d0d4bb802c5817e2fbf5452f']"

  strings:
    $hex_string = { 7d b4 c1 85 11 a6 48 f0 25 a9 96 07 8b 0e d0 ae fe bf 5c e0 50 d8 98 f3 e5 2c db 3f 5e 33 5d b5 92 ce 2e 5b 67 83 29 af 3e 4e 34 10 45 13 08 bd f1 9e 7e ad b3 a4 ec aa 36 1f 14 4d c2 6f 31 b8 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}