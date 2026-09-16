rule i3ed_1b90dfa959eb0912 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=i3ed.1b90dfa959eb0912"
    cluster      = "i3ed.1b90dfa959eb0912"
    cluster_size = "299"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171117"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "backdoor padodor symmi"
    md5_hashes   = "['001d8df075a1d1dc772b0f4f00a50dd9','015cda91106a56f41c8f973a7d52bd70','170b3d013686a21570d1bba0b40632c8']"

  strings:
    $hex_string = { 7b 08 8d 0c 76 8b 34 8f e9 62 ff ff ff 31 c0 eb 19 55 8d 6b 10 6a ff 53 e8 a5 fe ff ff 83 c4 0c 6a 0b e8 33 04 00 00 83 c4 04 5d 5f 5e 5b 89 ec 5d c3 55 89 e5 53 56 57 83 7d 0c 01 75 05 e8 23 }

  condition:
    filesize > 4096 and filesize < 16384
    and $hex_string
}