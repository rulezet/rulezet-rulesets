rule n3f1_119096c9cc000b12 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=n3f1.119096c9cc000b12"
    cluster      = "n3f1.119096c9cc000b12"
    cluster_size = "3"
    filetype     = "application/zip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171123"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "opfake androidos fakeinst"
    md5_hashes   = "['6c0d8895b618ef2f21d9f126a9bd0e1a','db0a69e665e36c18d049d4d6db2d1dbd','fd5a82fa210838d757ce11be0854efdb']"

  strings:
    $hex_string = { 25 ce 6d 91 13 3e d9 0f bf 6e 41 cb 20 7c d5 aa 86 1f 0b 0d e8 7e 5e 0e 42 1b f8 14 cd 16 e1 d1 fd 72 19 4b e2 a4 90 bb 79 e4 53 ca 36 7f 76 28 f5 d2 5c b8 a3 f7 95 10 26 4e 40 2d b7 34 4c 9f }

  condition:
    filesize > 262144 and filesize < 1048576
    and $hex_string
}