rule j3f0_01a61e051ee31112 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=j3f0.01a61e051ee31112"
    cluster      = "j3f0.01a61e051ee31112"
    cluster_size = "4"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171118"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "zusy malicious malob"
    md5_hashes   = "['022e8d0feada5163d31e938751d175c9','5d7386cff695289ff0e8b472f839ec34','fcfe1031ca4e6f8937f15c48db64aec8']"

  strings:
    $hex_string = { b1 58 04 5e 09 80 18 68 20 15 23 bf 14 3c 12 51 c4 b0 48 d2 44 5e 31 01 be 9e 24 c0 70 6c 38 40 4d ec 0e 03 bc 6d fd 03 c4 22 60 5c b4 0e a0 26 61 9c 68 0c 40 50 00 58 f0 79 19 d5 06 4d e4 a1 }

  condition:
    filesize > 4096 and filesize < 16384
    and $hex_string
}