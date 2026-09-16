rule p3f7_3912d19cea210912 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=p3f7.3912d19cea210912"
    cluster      = "p3f7.3912d19cea210912"
    cluster_size = "20"
    filetype     = "ASCII text"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "androidos triada ransomkd"
    md5_hashes   = "['10833c9178e416e0e238c80659004242','3196dcefe2054765239c4dff1cbd967c','c48cfd64e21b9ae3f972ed2877a11f6b']"

  strings:
    $hex_string = { 6a 08 a9 a3 f5 e8 f7 ba ea b2 46 cb 84 a6 01 c1 23 4a bb 39 d5 2c 9e 05 ca e6 25 53 d2 7c c6 f3 2a 79 8e d7 c8 e3 be 8a 0c fe dd 20 9f 78 37 f8 59 82 19 2b cd ed aa d9 ec d4 d8 6b 40 d0 47 7f }

  condition:
    filesize > 4194304 and filesize < 16777216
    and $hex_string
}