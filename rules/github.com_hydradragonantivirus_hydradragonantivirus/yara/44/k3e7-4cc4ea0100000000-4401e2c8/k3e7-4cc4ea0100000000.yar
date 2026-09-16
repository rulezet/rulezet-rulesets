rule k3e7_4cc4ea0100000000 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e7.4cc4ea0100000000"
    cluster      = "k3e7.4cc4ea0100000000"
    cluster_size = "9"
    filetype     = "application/octet-stream"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171122"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "metasploit androidos hacktool"
    md5_hashes   = "['24188ed65cf6bedcf6654156e7c98a13','56d00deaadc0c1da048fd85e111fbcbc','d9a1680a474c65cb5fc6d31abbf0f26e']"

  strings:
    $hex_string = { 07 76 61 6c 75 65 4f 66 00 06 76 65 72 69 66 79 00 05 77 72 69 74 65 00 00 00 01 01 0b 81 80 04 88 19 0d 04 a0 19 00 00 01 01 0e 81 80 04 c4 19 0f 01 dc 19 00 00 03 02 10 81 80 04 8c 1a 03 09 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}