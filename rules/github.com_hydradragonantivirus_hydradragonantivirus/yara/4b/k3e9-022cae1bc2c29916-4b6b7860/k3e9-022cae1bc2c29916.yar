rule k3e9_022cae1bc2c29916 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e9.022cae1bc2c29916"
    cluster      = "k3e9.022cae1bc2c29916"
    cluster_size = "6"
    filetype     = "PE32 executable (GUI) Intel 80386"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "berbew genpack qukart"
    md5_hashes   = "['1836b29890c055104eac83992b6a6aec','a2c6f94885a92850351769eadda4cbb4','e482cafb5db09221d2de3398c9c98820']"

  strings:
    $hex_string = { cd 01 53 65 74 53 65 63 75 72 69 74 79 49 6e 66 6f 00 00 00 d4 01 53 65 74 45 6e 74 72 69 65 73 49 6e 41 63 6c 41 00 00 18 00 5f 5f 47 65 74 4d 61 69 6e 41 72 67 73 00 81 01 5f 73 6c 65 65 70 }

  condition:
    filesize > 65536 and filesize < 262144
    and $hex_string
}