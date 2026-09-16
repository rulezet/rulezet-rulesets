rule i2321_07179e89c9000b12 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=i2321.07179e89c9000b12"
    cluster      = "i2321.07179e89c9000b12"
    cluster_size = "6"
    filetype     = "application/gzip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171124"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "cosmicduke backdoor razy"
    md5_hashes   = "['42d654728adf147c1f1ca3ad355e1cb9','5343b630a56188803520641d29103413','e1bc5edd7c368032fee5ff5ad3956265']"

  strings:
    $hex_string = { 8c 65 69 ed 85 ac bf 7a 4c db 7d 0d 77 22 f7 1b 6b 2a b6 9c 8b 3d cd c5 f4 e2 7f 39 d6 50 d8 15 ef 87 62 ad bd 21 7d af fd 74 f0 ee 9e fc 36 e6 f7 c4 d3 f0 f2 a6 d8 50 5c f3 b6 18 7b 6d 53 ec }

  condition:
    filesize > 1024 and filesize < 4096
    and $hex_string
}