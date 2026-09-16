rule n3f7_4910a08bc6220b12 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=n3f7.4910a08bc6220b12"
    cluster      = "n3f7.4910a08bc6220b12"
    cluster_size = "93"
    filetype     = "text/html"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171122"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "clicker faceliker script"
    md5_hashes   = "['01c5a0bb2063d21d450514c6da794c5d','06643bbd2f2384032ae2451080ed21e1','3c53682069af6e7f3e9dc6491aa21201']"

  strings:
    $hex_string = { 4c 46 e8 a8 88 e7 94 bb 20 2d 6c 65 6e 66 72 69 65 64 20 70 72 6f 6a 65 63 74 2d 20 5b 33 34 36 50 31 36 31 4d 42 5d 20 44 4f 57 4e 4c 4f 41 44 20 4c 49 4e 4b 53 3a 20 46 72 65 61 6b 53 68 61 }

  condition:
    filesize > 262144 and filesize < 1048576
    and $hex_string
}