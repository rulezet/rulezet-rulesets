rule o231d_611495e1ca000b12 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=o231d.611495e1ca000b12"
    cluster         = "o231d.611495e1ca000b12"
    cluster_size    = "19"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180911"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "fakeapp androidos scamapp"
    md5_hashes      = "['ef103f76a612d1fba7040dc9c40268db2216755c','cf94d514bb43a878ac68467f5bfff13db79ff92f','4125db669f0c2ba57eb685c886d3c46bcc7fadcc']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=o231d.611495e1ca000b12"

  strings:
    $hex_string = { c7 bb 55 df 05 71 26 32 80 7e e8 7f fc f9 e7 5f ee 8f ff fa d7 cf fb c3 9c 6b 1d 09 9a 11 ec 74 38 1c f7 87 65 49 e6 40 2d 77 6c 06 8d 48 70 be 15 03 42 12 41 30 d0 54 10 3c 90 98 5a d6 ea 4d }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}