rule k3e9_0119bce9c8800b12 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e9.0119bce9c8800b12"
    cluster      = "k3e9.0119bce9c8800b12"
    cluster_size = "5"
    filetype     = "PE32 executable (GUI) Intel 80386"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171117"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "mydoom email banker"
    md5_hashes   = "['15d2403edac346778367905ad55e56ce','22b450bc623f633fe86bdff117249c5f','9e97a445a24a656523b116d56967770b']"

  strings:
    $hex_string = { a7 5b 26 9b 85 52 d9 87 42 54 a8 d2 5f 6a be e4 8d d6 1e 20 2a 65 ed 01 29 e7 f8 e2 da fd c3 a3 09 48 13 2d 31 15 56 46 a6 80 35 c6 e5 cd f1 00 51 1f 3d 12 03 70 90 95 4a 4d d5 3a 50 f6 8e e1 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}