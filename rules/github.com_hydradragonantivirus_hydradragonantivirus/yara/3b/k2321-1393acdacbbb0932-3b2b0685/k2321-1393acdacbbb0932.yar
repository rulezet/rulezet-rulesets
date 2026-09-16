rule k2321_1393acdacbbb0932 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k2321.1393acdacbbb0932"
    cluster      = "k2321.1393acdacbbb0932"
    cluster_size = "26"
    filetype     = "application/gzip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "androm backdoor symmi"
    md5_hashes   = "['0cbee0ff53789e7f4b889513114e04a3','0ff570c9a8ed7adaa1f24f7fa915c540','ae7b79f3713f56ecaafad32878ee3467']"

  strings:
    $hex_string = { 19 2d f4 0f 65 2f 1c e5 25 97 af ae a0 73 28 11 7f c5 1b c1 1a 20 d8 08 76 0a fd 5d 52 00 f5 6d 41 e0 9e 62 a2 9d b3 c6 85 74 3c ba a1 07 13 09 d1 ad 14 35 4a 9f 86 27 aa fc 1f ca 53 93 54 05 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}