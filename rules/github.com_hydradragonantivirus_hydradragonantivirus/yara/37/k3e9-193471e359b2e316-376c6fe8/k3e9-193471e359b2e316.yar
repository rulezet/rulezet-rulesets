rule k3e9_193471e359b2e316 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e9.193471e359b2e316"
    cluster      = "k3e9.193471e359b2e316"
    cluster_size = "4"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "installcore malicious unwanted"
    md5_hashes   = "['13a6a73d343a9eb158f39d10f97ae398','67701574952221973a1df438ec71498a','e8b85f4ecd4c0ed2e0342cb6ef1bf18a']"

  strings:
    $hex_string = { 98 40 4c 0e 49 83 46 58 c7 fe 45 e3 57 7d 4a e5 62 53 5d 61 1d 90 23 2e b9 43 00 7f cd e6 8a d9 28 eb 5f 55 17 ba 1f 6f ca 9d 1b ee 4f 80 18 20 08 d8 95 b3 aa c0 94 f2 32 d4 8e f3 d7 65 0b cb }

  condition:
    filesize > 262144 and filesize < 1048576
    and $hex_string
}