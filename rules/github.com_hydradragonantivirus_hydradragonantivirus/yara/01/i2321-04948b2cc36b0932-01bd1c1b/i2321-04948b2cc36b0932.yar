rule i2321_04948b2cc36b0932 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=i2321.04948b2cc36b0932"
    cluster      = "i2321.04948b2cc36b0932"
    cluster_size = "18"
    filetype     = "application/gzip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171124"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "backdoor cosmicduke razy"
    md5_hashes   = "['036b6c7a755276efba2a179b3404a7bd','0be52a47c9e0247b7b11df92da59a710','efd7dbddb62b21f0ce659cb7ad02702e']"

  strings:
    $hex_string = { b4 65 87 15 d9 a1 33 3b 14 b3 c3 63 d9 61 6c 6a 32 9b ea 86 ca eb 31 d0 67 ab 2f 1f 9d 6d 4e 97 9c 6a 9a da 98 b7 9f da b8 74 43 e5 fd 89 77 96 a4 d7 55 5f ee 38 71 f4 c7 8d 69 cb e4 b5 53 1b }

  condition:
    filesize > 1024 and filesize < 4096
    and $hex_string
}