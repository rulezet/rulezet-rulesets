rule o3e9_6291a848c0000b12 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=o3e9.6291a848c0000b12"
    cluster      = "o3e9.6291a848c0000b12"
    cluster_size = "769"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "driverupdate fakedriverupdate sality"
    md5_hashes   = "['00738c68914cf0b7ae83d52cea2beda9','00e5996a0bd64283e5e9d86ad0ff9ee5','03f5ae3eccb9a74252c42d8467d5d1ae']"

  strings:
    $hex_string = { 52 90 2e 60 87 ef c5 7d d7 58 56 c4 1e ed 42 5e 09 2c 8c 3a fb 0b 72 39 27 d1 b5 ae 36 37 02 a0 0d 79 01 8f 68 51 c6 1f c7 f9 10 ba e1 06 99 d0 41 04 45 de 0f 4e 4b c3 49 e5 b0 88 83 5b c0 34 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}