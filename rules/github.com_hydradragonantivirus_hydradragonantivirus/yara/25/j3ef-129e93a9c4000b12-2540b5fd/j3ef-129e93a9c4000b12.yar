rule j3ef_129e93a9c4000b12 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=j3ef.129e93a9c4000b12"
    cluster      = "j3ef.129e93a9c4000b12"
    cluster_size = "8"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "malicious kranet auno"
    md5_hashes   = "['6719fa9a10a7b160259fcf1238031f1b','693596d361bd521f755216827500c8cd','fb54cb70310f094a08e105dd9ffcacb5']"

  strings:
    $hex_string = { 39 2d 39 41 35 35 2d 44 30 46 42 46 42 45 37 45 43 44 33 7d 00 00 6b 65 72 6e 65 6c 33 32 2e 64 6c 6c 00 00 49 73 57 6f 77 36 34 50 72 6f 63 65 73 73 00 00 53 6f 66 74 77 61 72 65 5c 4d 69 63 }

  condition:
    filesize > 4096 and filesize < 16384
    and $hex_string
}