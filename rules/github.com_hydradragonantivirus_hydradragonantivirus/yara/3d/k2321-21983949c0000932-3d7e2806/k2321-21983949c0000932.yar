rule k2321_21983949c0000932 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k2321.21983949c0000932"
    cluster      = "k2321.21983949c0000932"
    cluster_size = "3"
    filetype     = "application/gzip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171124"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "nitol fdld dropped"
    md5_hashes   = "['107fd3ed1f4ea6947cdc962453046569','bb49c897b617ed6de974091927492a89','d0bc9e46fa2d21ad2ab2ad5696a1e65e']"

  strings:
    $hex_string = { d3 2f 4c 50 6c ea 84 c5 a6 51 b1 6f 72 6d 8b 0e 58 b1 e6 9f f0 c7 ba 9d 78 0c ce 37 c9 c2 e7 4d 91 b6 4f 48 c0 ad 95 54 fd d6 f3 ac df 7a 81 0d 68 cf 86 02 67 f5 87 b4 7f fa 65 09 29 06 1b 34 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}