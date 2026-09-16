rule j3e7_7114d6e3c8000330 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=j3e7.7114d6e3c8000330"
    cluster      = "j3e7.7114d6e3c8000330"
    cluster_size = "117"
    filetype     = "application/octet-stream"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171122"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "shedun androidos risktool"
    md5_hashes   = "['00844fe5513c1d53f8a0e2eebe5569ef','009e04b8a09dab6ad860fcc80dded78f','1becf5dd447e15cd3c956c6efdb8d662']"

  strings:
    $hex_string = { 79 54 68 72 65 61 64 00 06 65 78 69 73 74 73 00 07 66 6f 72 4e 61 6d 65 00 03 67 65 74 00 0f 67 65 74 41 62 73 6f 6c 75 74 65 50 61 74 68 00 12 67 65 74 41 70 70 6c 69 63 61 74 69 6f 6e 49 6e }

  condition:
    filesize > 4096 and filesize < 16384
    and $hex_string
}