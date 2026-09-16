rule o3e9_6d94084adabb0912 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=o3e9.6d94084adabb0912"
    cluster      = "o3e9.6d94084adabb0912"
    cluster_size = "4582"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171109"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "imali crossrider rftt"
    md5_hashes   = "['0000744c921b1efdefa0334684a21a5d','000a8bb9b51541d53691483fbc74b2e6','00e08a9b517b60e77d6797d63cb46524']"

  strings:
    $hex_string = { 38 be 53 7d f4 d2 92 61 c4 f6 e9 36 79 6a e9 d8 16 36 d9 00 f0 e7 4b c8 a8 2d c6 5a 70 28 00 9d c0 77 bd f2 25 63 61 7c 53 1f 84 06 de 9a 50 5a 17 27 d5 d8 f4 ca 1b d8 12 17 78 b7 de 54 29 eb }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}