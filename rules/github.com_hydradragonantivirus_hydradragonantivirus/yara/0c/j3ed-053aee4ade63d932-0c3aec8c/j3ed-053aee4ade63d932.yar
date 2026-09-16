rule j3ed_053aee4ade63d932 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=j3ed.053aee4ade63d932"
    cluster      = "j3ed.053aee4ade63d932"
    cluster_size = "13"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "graftor malicious atraps"
    md5_hashes   = "['03d6dad6b05488f64e7efa30ac68d156','08b75e0a81b447608c00bae79f2b8b40','f71504511d67209d923b3a9f717d72ed']"

  strings:
    $hex_string = { 10 33 d2 42 d1 e2 81 c2 b4 f1 c9 01 03 c2 2b d2 8d 82 00 bd ff db 05 03 93 00 34 b9 60 54 81 8d 50 89 0c 24 8b 0c 24 81 e9 f5 ee 0e 1f 51 8f 04 24 50 5a 8f 00 40 c7 42 04 7f da 99 b3 48 83 6a }

  condition:
    filesize > 4096 and filesize < 16384
    and $hex_string
}