rule k3e9_6a92d794669b1912 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e9.6a92d794669b1912"
    cluster      = "k3e9.6a92d794669b1912"
    cluster_size = "508"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "convertad nsis malicious"
    md5_hashes   = "['00136d53fccdb975a2c39a08af4dc793','0101c1b855cd03b1f1e5c56968a1c19d','081703eca742bf653b2bc7f5ca058d63']"

  strings:
    $hex_string = { d0 32 77 13 b8 cd a2 81 cc c1 22 93 d6 e9 3e 7d 34 94 f3 51 1f a1 7c 99 01 35 a7 a5 0a ed 12 c2 ac bd a9 bf e8 dd c0 62 f8 bb 3d 96 b7 be 38 23 03 42 92 7a ec fd 6e ff e6 a4 ea db a3 47 31 9f }

  condition:
    filesize > 65536 and filesize < 262144
    and $hex_string
}