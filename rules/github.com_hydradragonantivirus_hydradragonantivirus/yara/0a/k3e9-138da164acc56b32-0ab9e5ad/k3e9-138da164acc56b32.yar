rule k3e9_138da164acc56b32 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e9.138da164acc56b32"
    cluster      = "k3e9.138da164acc56b32"
    cluster_size = "4"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171119"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "virut virtob malicious"
    md5_hashes   = "['a182bdab4c8e69b7bf3773137ae55bd2','a713336b1cf2297ba7bcf367e0d95f46','ebae705a15f88cf7857f14baca624ec8']"

  strings:
    $hex_string = { c9 c3 2e 8b c0 8a 06 88 07 8a 46 01 88 47 01 8a 46 02 88 47 02 8b 45 08 5e 5f c9 c3 90 8d 74 31 fc 8d 7c 39 fc f7 c7 03 00 00 00 75 24 c1 e9 02 83 e2 03 83 f9 08 72 0d fd f3 a5 fc ff 24 95 40 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}