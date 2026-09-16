rule k3e7_1a2b0e669cfb1130 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e7.1a2b0e669cfb1130"
    cluster      = "k3e7.1a2b0e669cfb1130"
    cluster_size = "438"
    filetype     = "application/octet-stream"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171122"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "smforw smsspy androidos"
    md5_hashes   = "['000539b33da8d44c5fd78bc570186196','0044bd46cc73f197de87e4670a31451d','078bab08c04507ed18bc53b9a45f7028']"

  strings:
    $hex_string = { 26 68 3c 02 5b 1d e1 03 0f b3 03 5c 5a 01 13 10 2d 1e 2d 69 28 50 03 0e 9b 03 2c 6e 3c 2d 1e 2d 83 4e 03 0d 9a 03 2c 6c 3c 88 01 19 14 02 6a 4a 05 0d a5 03 12 ad 05 5c a5 01 10 17 05 12 06 0d }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}