rule k3e9_15eb149bda2303b2 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e9.15eb149bda2303b2"
    cluster      = "k3e9.15eb149bda2303b2"
    cluster_size = "49"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171117"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "upatre kryptik malicious"
    md5_hashes   = "['087e561fb6d18af96d1d1c68d0f0d5fd','09e8592536017880ce12c682706d57b7','a2484190ecb3b51e406dcf3ec166f5d8']"

  strings:
    $hex_string = { 00 61 62 63 64 65 66 67 68 69 6a 6b 6c 6d 6e 6f 70 71 72 73 74 75 76 77 78 79 7a 41 42 43 44 45 46 47 48 49 4a 4b 4c 4d 4e 4f 50 51 52 53 54 55 56 57 58 59 5a 30 31 32 33 34 35 36 37 38 39 5f }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}