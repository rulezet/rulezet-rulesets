rule k3e9_69d09ce957ab0b12 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e9.69d09ce957ab0b12"
    cluster      = "k3e9.69d09ce957ab0b12"
    cluster_size = "124"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171118"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "mywebsearch riskware toolbar"
    md5_hashes   = "['03172d9b1199f2f0f8a59d2f1e964948','074b11beadd6434c46c2d22802e775b6','2c301d610d119588ee86090392bf5ed4']"

  strings:
    $hex_string = { a6 17 c5 7b ef 19 02 6b 7a 84 3a 83 d7 27 74 e8 c3 bf 82 80 44 0e f5 ef 98 d0 ae 0d c9 5b c7 0b 4e 13 e7 34 a9 47 3e e6 8e 93 40 0f 99 49 46 fa 85 9e 8c 28 9b 95 44 00 cc 4c a4 15 a1 fe f6 ea }

  condition:
    filesize > 262144 and filesize < 1048576
    and $hex_string
}