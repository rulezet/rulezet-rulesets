rule k3e9_6a92979c1ea31912 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e9.6a92979c1ea31912"
    cluster      = "k3e9.6a92979c1ea31912"
    cluster_size = "7"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171118"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "nsis adload keygen"
    md5_hashes   = "['0f1bae9725f934f765f1bb4d3a70b0c5','365305417ad90c3b32f5330e9143c093','cfed51e40a1764f0db9f1f3463e91cb9']"

  strings:
    $hex_string = { c0 7c 2b 56 8d 70 41 c1 e6 05 57 03 f1 8d 78 01 8b 06 85 c0 74 10 83 7e fc ff 75 0a 50 ff 15 04 30 00 10 83 26 00 83 ee 20 4f 75 e4 5f 5e c3 51 8b 44 24 08 53 55 56 8b 98 14 08 00 00 57 89 5c }

  condition:
    filesize > 262144 and filesize < 1048576
    and $hex_string
}