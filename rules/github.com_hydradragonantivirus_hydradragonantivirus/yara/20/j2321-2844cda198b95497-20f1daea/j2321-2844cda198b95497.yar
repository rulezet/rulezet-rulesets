rule j2321_2844cda198b95497 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=j2321.2844cda198b95497"
    cluster      = "j2321.2844cda198b95497"
    cluster_size = "10"
    filetype     = "application/gzip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171124"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "generickd waski androm"
    md5_hashes   = "['07bec62a36200988262d05140599c489','0e033536eb7b20c88f949acaaba2cbd8','efe964cfff906441ebe0ed815f58eac4']"

  strings:
    $hex_string = { cb 2b 35 c9 de 3e 29 b6 b3 33 f6 b4 44 72 1a c5 49 9a 9a d2 ef 7b f7 4e 1f eb ec 3c 76 fa 5e d6 9b 63 9d bf 94 ad ab 3a 55 77 a0 a2 e2 40 dd 8d 93 6b 6f 26 b6 27 d5 5d b9 92 d9 bc f5 75 66 e6 }

  condition:
    filesize > 4096 and filesize < 16384
    and $hex_string
}