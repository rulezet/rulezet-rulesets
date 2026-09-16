rule k3e9_0b94e448c4000b16 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e9.0b94e448c4000b16"
    cluster      = "k3e9.0b94e448c4000b16"
    cluster_size = "6"
    filetype     = "PE32 executable (GUI) Intel 80386"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "small generickd upatre"
    md5_hashes   = "['2ebcb72df18a11d3c5ec1ed0d9ade342','404b8cf772b08f59b285552e30a986fe','f68357661a6dc8ce9c6d5d32394c654a']"

  strings:
    $hex_string = { 44 f4 cd 9c 63 1d e5 40 b4 d8 c5 1e 88 ff 00 c3 e2 f5 3e 3a 8b b1 46 24 fe 9e b8 42 7e df f1 e4 a8 2d 87 d6 ca 5c 47 5a c7 87 ea 77 d9 25 6e b9 45 13 75 6d 27 eb bf 93 5d d1 f7 e8 fe 10 a2 2c }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}