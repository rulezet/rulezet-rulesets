rule n3f1_291992b9c9800b12 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=n3f1.291992b9c9800b12"
    cluster      = "n3f1.291992b9c9800b12"
    cluster_size = "217"
    filetype     = "application/zip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171122"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "slocker congur jisut"
    md5_hashes   = "['00287ed735bcc463c50c7eb042943281','0121cac907cd7950175ab9bf9f9afdba','11778581e4a8e1020550179d22b789bb']"

  strings:
    $hex_string = { 07 57 25 96 99 e3 40 26 47 1e 05 4e 08 7a 5a 6c 24 e1 85 f7 ca a6 46 52 1b 77 9b 23 9f ba 7b db f0 12 d9 1f cb 01 33 74 a5 19 c0 36 a2 b3 a0 2d 65 3d 54 4b d2 d8 9e 24 2c 0e 7c 92 c6 d1 8a 6a }

  condition:
    filesize > 262144 and filesize < 1048576
    and $hex_string
}