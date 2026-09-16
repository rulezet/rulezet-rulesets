rule k3e9_1f4efcc1c8000112 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e9.1f4efcc1c8000112"
    cluster      = "k3e9.1f4efcc1c8000112"
    cluster_size = "60365"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171122"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "upatre generickd archsms"
    md5_hashes   = "['00026ceb6e105788787c418fe0049e85','0004578c1ac9bfa5c6aae029ab513f58','001cf667ce813bead5eb2e0b9a745a02']"

  strings:
    $hex_string = { 7c 8a e1 72 1c 73 4f 67 bf 06 cb 65 ee e1 a9 77 a6 b6 ec 8d 1b dc 99 ca 28 46 04 17 c2 35 26 00 dc ce f3 21 9c 13 56 e6 cc 40 bc 31 16 58 22 43 39 d6 57 32 81 3d fc 9f 89 c5 2b c3 c6 08 e2 fd }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}