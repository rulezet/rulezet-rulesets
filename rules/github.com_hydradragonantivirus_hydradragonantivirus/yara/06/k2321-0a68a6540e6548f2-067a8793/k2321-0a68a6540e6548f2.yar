rule k2321_0a68a6540e6548f2 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k2321.0a68a6540e6548f2"
    cluster      = "k2321.0a68a6540e6548f2"
    cluster_size = "6"
    filetype     = "application/gzip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171124"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "tinba zusy backdoor"
    md5_hashes   = "['ba13d0804a153a3e91cd85ddeb4a25d8','bd8135145b0a2c8182fa65771c1ab67d','f3f4babb8c40f520d38be044896ec307']"

  strings:
    $hex_string = { 11 6e 96 bf a4 c6 c3 c5 85 f2 44 48 28 47 f8 a5 6c f1 67 2e fc 5c 0d 18 45 f5 82 6b 97 e7 ad 7d a8 f6 70 33 b5 7b 16 d5 0c ae ee fd bc 35 29 36 26 63 c1 cf 3e ff 00 ea 04 5c 23 c2 3b fa 51 2f }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}