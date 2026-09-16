rule j2321_32126d6284992937 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=j2321.32126d6284992937"
    cluster      = "j2321.32126d6284992937"
    cluster_size = "4"
    filetype     = "PE32 executable (GUI) Intel 80386"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171118"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "small generickd upatre"
    md5_hashes   = "['ab450594ef01e40a6dd8c5a38954b729','ac32871630f64fb02522746f35396736','ffcd7d91304ff255d4b9e9d3cd0b63ee']"

  strings:
    $hex_string = { 06 11 7a aa 43 7d 48 a4 ae 90 95 58 67 8e f5 35 23 c9 e2 bc 37 27 38 54 e8 72 3d 51 74 2c ca 14 dc 3b f0 39 f8 57 07 87 1a 13 ee f9 70 df 2b 17 8d 48 5c d7 fe 66 d0 4c 6e 0c ea 30 6e 9c 20 b7 }

  condition:
    filesize > 4096 and filesize < 16384
    and $hex_string
}