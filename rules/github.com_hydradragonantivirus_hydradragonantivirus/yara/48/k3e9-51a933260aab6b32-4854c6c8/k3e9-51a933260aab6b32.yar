rule k3e9_51a933260aab6b32 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e9.51a933260aab6b32"
    cluster      = "k3e9.51a933260aab6b32"
    cluster_size = "9"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "chir runouce virut"
    md5_hashes   = "['18b1feb3ecd0e43086af1e17da1ee87c','1f8863e993f55ae5ef8f8facdc507f67','c68c012afaf408f78128623ccff1adb8']"

  strings:
    $hex_string = { 05 80 f9 7e 72 2e 33 c0 fc aa 80 fe 01 75 bb 80 fa 01 72 b6 2b fc 83 ff 06 72 af 8a 04 24 3c 40 74 a8 3c 2e 74 a4 54 e8 48 ff ff ff eb 9c fe c2 eb 02 fe c6 8a c1 fc aa eb 94 53 ff 56 40 81 c4 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}