rule k2321_1b929cc9cc000b12 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k2321.1b929cc9cc000b12"
    cluster      = "k2321.1b929cc9cc000b12"
    cluster_size = "6"
    filetype     = "PE32 executable (GUI) Intel 80386"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171117"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "rincux ddos stormattack"
    md5_hashes   = "['1fd0eb8d0d23a2fb93dd4f9e5f89d192','3b8ebace5352c55bb079f9e3eb2b1f46','f7303647c2dbcc93107ea1546a86e457']"

  strings:
    $hex_string = { bd cc 42 81 2a 8c 34 ae 8b 92 83 05 14 49 ec 9f f0 8f 12 94 0a b3 28 be d8 4c 49 88 07 62 ca 24 97 29 8e c4 0e 21 23 6e 4f c6 fb e9 e8 ea 93 ce 44 8a 3d 15 6f 1f d9 3f 84 47 09 de 48 c5 a3 04 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}