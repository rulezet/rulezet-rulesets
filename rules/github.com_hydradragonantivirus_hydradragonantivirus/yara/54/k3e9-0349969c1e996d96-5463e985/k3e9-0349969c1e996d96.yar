rule k3e9_0349969c1e996d96 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e9.0349969c1e996d96"
    cluster      = "k3e9.0349969c1e996d96"
    cluster_size = "4054"
    filetype     = "PE32 executable (GUI) Intel 80386"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171122"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "generickd softcnapp taranis"
    md5_hashes   = "['001b5a0fb7844ef168d263449ff65c2f','001c2428781ecb83347965993aa4b86e','00e2fa2cbd7ed1da202355efadf4838d']"

  strings:
    $hex_string = { 46 41 fb af 01 e5 9f 6f d5 ba 0f 18 9c f4 63 4b 77 5b 6a 1a 88 7a 9b 12 c9 ae db 54 3a b7 f1 e7 38 05 11 3f 5c d6 b2 29 c8 20 a9 45 71 fd fe b3 03 0e f3 95 c1 2d 25 13 48 74 bb 33 dc ee e4 93 }

  condition:
    filesize > 65536 and filesize < 262144
    and $hex_string
}