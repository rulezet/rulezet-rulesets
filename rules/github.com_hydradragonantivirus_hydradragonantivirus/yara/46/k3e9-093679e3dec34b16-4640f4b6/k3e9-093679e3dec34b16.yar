rule k3e9_093679e3dec34b16 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e9.093679e3dec34b16"
    cluster      = "k3e9.093679e3dec34b16"
    cluster_size = "84"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171123"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "unwanted installcore advml"
    md5_hashes   = "['00e02f8c334aa70200ed2c6f57b1768f','00ed6c5ded785a6312d82bb64a20efed','3d9dffd2d7ff3164e89ebb2c0ad8d0d0']"

  strings:
    $hex_string = { 44 49 d5 da b6 b4 32 b2 83 19 d3 6d 3f de ec 78 3b b8 8f a9 5e 6a c9 f8 e9 02 07 16 aa a4 04 b0 fd 96 71 f3 db be 31 e0 4e 00 98 1a 24 c6 23 e1 3a 46 35 85 03 43 a5 a0 1d 5b 34 54 f2 a6 8e 7e }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}