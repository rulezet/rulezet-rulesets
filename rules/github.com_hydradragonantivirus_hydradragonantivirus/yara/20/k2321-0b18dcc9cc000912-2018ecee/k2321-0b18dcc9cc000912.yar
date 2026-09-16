rule k2321_0b18dcc9cc000912 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k2321.0b18dcc9cc000912"
    cluster      = "k2321.0b18dcc9cc000912"
    cluster_size = "6"
    filetype     = "application/gzip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171124"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "rincux ddos stormattack"
    md5_hashes   = "['1b0fa20f7ca3260f2c0d5fb70be4573f','552820e2c89585a7f11d6343fa09482c','f344a134ef59eab5647cccffed44c66a']"

  strings:
    $hex_string = { dc 17 89 c3 c5 df 4a 1f c9 43 55 a7 f9 4b c6 96 e4 66 5f 83 69 0e 8b 63 cb 72 9f 78 07 6a 39 aa 27 64 ff 3a 9b 91 3e 7c 8e f6 9e 30 46 3d 87 23 66 76 77 0f fb cd 0c 6e c7 da 51 98 ec 74 53 01 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}