rule i3ed_051756abcc668932 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=i3ed.051756abcc668932"
    cluster      = "i3ed.051756abcc668932"
    cluster_size = "72"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "gamarue generickdz debris"
    md5_hashes   = "['0921a4ab2fa83045153357df95ad072d','09a6558ca5b3346f86e43d5928f54329','4a61ec1d6aaa3a874b4d0e47f65e492c']"

  strings:
    $hex_string = { 8d 71 fc 3b f0 72 12 8b 0e 85 c9 74 07 ff d1 a1 50 30 00 10 83 ee 04 eb ea 50 ff 15 10 20 00 10 83 25 50 30 00 10 00 59 5e 6a 01 58 c2 0c 00 55 8b ec 53 8b 5d 08 56 8b 75 0c 57 8b 7d 10 85 f6 }

  condition:
    filesize > 4096 and filesize < 16384
    and $hex_string
}