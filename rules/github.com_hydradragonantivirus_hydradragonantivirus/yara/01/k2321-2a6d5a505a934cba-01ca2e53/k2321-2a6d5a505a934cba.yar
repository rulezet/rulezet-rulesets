rule k2321_2a6d5a505a934cba {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k2321.2a6d5a505a934cba"
    cluster      = "k2321.2a6d5a505a934cba"
    cluster_size = "24"
    filetype     = "PE32 executable (GUI) Intel 80386"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "tinba zusy backdoor"
    md5_hashes   = "['182fd226fea5f68932afc78965010e5f','199bdc35d77dd070275fa736342ff888','c3934f59a9a48811a1a67ce18884ef63']"

  strings:
    $hex_string = { b6 29 c0 8f 49 b7 27 79 f6 da f1 91 37 9e 78 26 af a0 83 c5 82 b0 62 43 06 c9 db bf e3 87 5d 08 6e f0 1c 52 fe fd 3e 01 f7 fc 0d 95 d0 88 48 9d 32 ef d5 b1 4a 04 97 23 d8 03 c2 71 79 4c e7 56 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}