rule o3f1_11327844a9486f36 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=o3f1.11327844a9486f36"
    cluster      = "o3f1.11327844a9486f36"
    cluster_size = "53"
    filetype     = ""
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171123"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "riskware fakeapp androidos"
    md5_hashes   = "['040247a69e6539ff7613e19e60ecc12c','0468eddbb5b6952b25ef69d92118e29a','41f28e1dcddbfab40a7e1f74369f45c8']"

  strings:
    $hex_string = { 8e 2f a3 c1 f9 e5 34 87 4e 48 79 33 30 46 1b de c5 52 32 a1 6c fd 77 73 11 d0 4d 4b b3 2b af 1a 55 df b9 e8 25 ed 22 05 1c 0d 54 47 6a 5f 18 a7 43 72 66 7a bf f6 ad 76 b7 a9 50 71 4a 12 91 ab }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}