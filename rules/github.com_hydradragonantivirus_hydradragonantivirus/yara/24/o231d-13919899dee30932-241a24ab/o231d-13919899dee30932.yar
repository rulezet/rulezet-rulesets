rule o231d_13919899dee30932 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=o231d.13919899dee30932"
    cluster         = "o231d.13919899dee30932"
    cluster_size    = "5"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180911"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "gluper androidos riskware"
    md5_hashes      = "['7deb6bb4153ab37b14a7acebf403e6ac51f95799','2492162a996c84c351eeb4d0e28b08b171b5806d','b5b641ed74c2a1efaa8f66b629136161638f477e']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=o231d.13919899dee30932"

  strings:
    $hex_string = { 8b 99 ef bc 8c e6 96 b9 e5 8f af e5 9f b7 e8 a1 8c e3 80 8c 25 31 24 73 e3 80 8d e3 80 82 00 22 4c e9 9c 80 e8 a6 81 e4 bd bf e7 94 a8 e6 96 b0 e7 89 88 e6 9c ac e7 9a 84 20 47 6f 6f 67 6c 65 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}