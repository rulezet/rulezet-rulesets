rule o3e7_0bb11ee9c8800b32 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=o3e7.0bb11ee9c8800b32"
    cluster      = "o3e7.0bb11ee9c8800b32"
    cluster_size = "3"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171123"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "installmonstr dlboost malicious"
    md5_hashes   = "['3bccf748af19b3cdb6b8b0fc871c13c0','620d49130c1917f345eb83ba583b8c76','c6d443a5196827ed174f5a791677ad49']"

  strings:
    $hex_string = { 3b ab 24 61 49 3f 7d 4e af da 59 54 30 e2 1f f7 71 aa 98 35 b2 eb cf 7a c2 06 ce 1d ec ee 5d fd 9e a8 9b 84 3a ed 45 7e 44 08 fe 32 5e d0 81 df 44 94 6c ad 86 cd 4a c0 1b a0 00 15 bd 39 5b 63 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}