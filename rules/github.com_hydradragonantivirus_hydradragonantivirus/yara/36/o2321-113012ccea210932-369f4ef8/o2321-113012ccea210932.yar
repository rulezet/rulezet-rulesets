rule o2321_113012ccea210932 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=o2321.113012ccea210932"
    cluster      = "o2321.113012ccea210932"
    cluster_size = "16"
    filetype     = "application/gzip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "installmonster installmonstr riskware"
    md5_hashes   = "['00e34044eb185f05bdbeab7ea0cbdcbf','0a4a086d7114cc81b335e80f454b2c2c','ff003bac8b43615d16cc56089f74d34b']"

  strings:
    $hex_string = { 03 b2 18 33 ba 1a ef be b8 2f c0 c1 3b 24 0e 5d 5e 58 02 14 44 8b 29 05 a9 db b5 e2 80 90 d0 e3 f2 f7 b4 1f d9 1b 34 00 bd 5c d3 12 36 1e 92 67 2b fa 4b dc 73 fb 8d 3f 9b 59 66 38 56 83 4c 42 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}