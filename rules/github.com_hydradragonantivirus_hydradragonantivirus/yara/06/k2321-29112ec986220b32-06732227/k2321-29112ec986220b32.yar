rule k2321_29112ec986220b32 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k2321.29112ec986220b32"
    cluster      = "k2321.29112ec986220b32"
    cluster_size = "12"
    filetype     = "application/gzip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "brontok email pazetus"
    md5_hashes   = "['04124510fa8fd2d8fbe9d1a0e6eb00a6','5aa517df5b08716113b236435af391b5','fcdcd1eb5c5764ad3d5c7184f1fd31e4']"

  strings:
    $hex_string = { 64 bf dc 18 9e e8 16 4d 85 3c ca d9 c2 7c bd 8a b2 f3 1a d6 28 ed 33 b6 66 c5 9d 4d 0b 5d 5b 7a 10 91 35 8c f7 52 b1 3e 88 cc 0c 82 98 36 62 c3 53 04 38 b0 34 29 57 30 7b bc f0 11 58 8f 7e fd }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}