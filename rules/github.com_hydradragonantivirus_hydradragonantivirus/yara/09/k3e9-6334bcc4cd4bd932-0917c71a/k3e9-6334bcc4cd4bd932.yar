rule k3e9_6334bcc4cd4bd932 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e9.6334bcc4cd4bd932"
    cluster      = "k3e9.6334bcc4cd4bd932"
    cluster_size = "34"
    filetype     = ""
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171123"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "virut virtob virux"
    md5_hashes   = "['02a9995d9d270969fc0a6e2179735a5f','088fdff0464a912c1019340aa52add65','7764445bd200bd426f7be5942bbf180a']"

  strings:
    $hex_string = { d9 c1 e9 02 75 6c 88 07 47 4b 75 fa 5b 5e 8b 44 24 08 5f c3 89 17 83 c7 04 49 74 af ba ff fe fe 7e 8b 06 03 d0 83 f0 ff 33 c2 8b 16 83 c6 04 a9 00 01 01 81 74 de 84 d2 74 2c 84 f6 74 1e f7 c2 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}