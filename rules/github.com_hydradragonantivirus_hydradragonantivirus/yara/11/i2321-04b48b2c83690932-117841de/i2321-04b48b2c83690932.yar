rule i2321_04b48b2c83690932 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=i2321.04b48b2c83690932"
    cluster      = "i2321.04b48b2c83690932"
    cluster_size = "8"
    filetype     = "application/gzip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "backdoor cosmicduke razy"
    md5_hashes   = "['031c7f57e99fe49102960e46124f9339','2f61242ae4b3919667d69c6c2d57ccf6','ea5a59a1774980708c7635b7bac577b5']"

  strings:
    $hex_string = { af 3f 4a b2 9a 2c a2 2d df b9 7a fc ae b9 39 7e fd e6 8b f7 e4 9f e2 de 75 c6 ff 08 8f 5c 52 76 dd ad f3 ff 33 fd 72 3c 5b 1f 36 f7 f6 0d a6 5d a3 e5 ee c1 91 3d c3 a5 07 1e 1f 2a f5 a7 c9 b1 }

  condition:
    filesize > 1024 and filesize < 4096
    and $hex_string
}