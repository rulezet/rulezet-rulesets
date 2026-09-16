rule j3ec_69ad2960594af9b2 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=j3ec.69ad2960594af9b2"
    cluster      = "j3ec.69ad2960594af9b2"
    cluster_size = "119"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "fileinfector ayazmhii infector"
    md5_hashes   = "['029393ed3b8b98638a2083ae46366915','02dd65d374e077762161b2c99923296b','1ebfa636a38a31dfffd08919e230b11e']"

  strings:
    $hex_string = { 0e 03 02 f3 a4 08 8a 06 88 07 47 46 e2 f8 04 ac aa e2 fc 08 03 02 ff e4 02 54 c3 04 8b c4 ff e0 c7 45 30 2a 2e 65 78 66 c7 45 34 65 00 8d 45 5c 50 8d 5d 30 53 ff 95 b0 01 00 00 40 85 c0 0f 84 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}