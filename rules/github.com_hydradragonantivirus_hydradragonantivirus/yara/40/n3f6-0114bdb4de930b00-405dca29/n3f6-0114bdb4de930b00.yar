rule n3f6_0114bdb4de930b00 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=n3f6.0114bdb4de930b00"
    cluster      = "n3f6.0114bdb4de930b00"
    cluster_size = "139"
    filetype     = "application/x-iso9660-image"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "genieo bundlore geonei"
    md5_hashes   = "['0157f95ec1a8680880f2bc7bd883e769','029a19ed3e123e88c1aa42ce251a1511','1c93bb07c9499deac6050e1abe16a488']"

  strings:
    $hex_string = { 04 a1 69 15 48 6d 1e 63 0a d1 0b 91 2b c8 6e 89 eb 13 2d 83 a8 32 00 21 00 e2 03 94 51 44 ca a6 99 2a 61 a5 97 a0 64 54 fb 2c 9c 3c c1 50 47 05 4b d6 8f 5d d4 56 14 5d 8a 34 b0 c9 16 91 07 10 }

  condition:
    filesize > 262144 and filesize < 1048576
    and $hex_string
}