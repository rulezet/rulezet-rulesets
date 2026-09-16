rule k3e9_6a92d794fae10912 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e9.6a92d794fae10912"
    cluster      = "k3e9.6a92d794fae10912"
    cluster_size = "111"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "adload nsis malicious"
    md5_hashes   = "['02937f06fde736598e6b7d2b0e08130d','0545ef01ec6e5308cb8dfd675193479c','2d2299ed4c39fe5212842dac67c4c268']"

  strings:
    $hex_string = { 45 e8 2b c7 3b d8 7e 02 8b d8 3b 5d e0 7d 08 8b 5d e0 eb 03 83 c3 14 33 c0 6a 01 50 50 53 ff 75 fc 50 ff 75 08 ff 15 d8 40 00 10 5f 5e 5b c9 c3 51 51 53 55 56 8b 74 24 18 57 8b 3d c4 40 00 10 }

  condition:
    filesize > 65536 and filesize < 262144
    and $hex_string
}