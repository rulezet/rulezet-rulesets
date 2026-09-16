rule o3e9_33892949c0000916 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=o3e9.33892949c0000916"
    cluster      = "o3e9.33892949c0000916"
    cluster_size = "334"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171111"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "downloadsponsor unwanted chipdigita"
    md5_hashes   = "['00275ebca9bc504ff6f17281f8a07efa','018c1ab01fcae932ad68fd732f954d4e','107a085a17113ef25990d71846140589']"

  strings:
    $hex_string = { 0e 2c 4b b0 e1 5a b6 6d 17 92 84 1b 57 ee 5c ba 75 ed de 25 69 12 65 cb 22 29 4a 6c 80 10 61 c2 60 c2 85 0d 0f a6 90 38 71 05 c6 8d 1d 3f 86 1c b9 b1 05 ca 95 2d 5f c0 9c 59 f3 66 ce 9d 3d 7f }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}