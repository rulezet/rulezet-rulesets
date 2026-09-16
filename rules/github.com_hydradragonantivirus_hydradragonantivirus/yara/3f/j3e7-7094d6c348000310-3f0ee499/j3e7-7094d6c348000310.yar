rule j3e7_7094d6c348000310 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=j3e7.7094d6c348000310"
    cluster      = "j3e7.7094d6c348000310"
    cluster_size = "64"
    filetype     = "application/octet-stream"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171122"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "shedun androidos risktool"
    md5_hashes   = "['01a0518bacc591108a3cc3c4077db9c6','0c6c377f85000f19650075fc23c1a584','592bf4da0bf86dc6b9c7f2dd1f736558']"

  strings:
    $hex_string = { 0d 67 65 74 50 61 72 65 6e 74 46 69 6c 65 00 07 68 61 73 4e 65 78 74 00 04 69 6e 66 6f 00 06 69 6e 76 6f 6b 65 00 08 69 74 65 72 61 74 6f 72 00 03 6a 61 72 00 10 6d 41 6c 6c 41 70 70 6c 69 63 }

  condition:
    filesize > 4096 and filesize < 16384
    and $hex_string
}