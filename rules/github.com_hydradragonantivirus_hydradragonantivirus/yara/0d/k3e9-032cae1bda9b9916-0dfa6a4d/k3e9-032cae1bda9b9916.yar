rule k3e9_032cae1bda9b9916 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e9.032cae1bda9b9916"
    cluster      = "k3e9.032cae1bda9b9916"
    cluster_size = "6"
    filetype     = "PE32 executable (GUI) Intel 80386"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "berbew qukart backdoor"
    md5_hashes   = "['3ea7f5c0feb8a132a25e0de7d6be7233','a456bf3de1ee95755511d8d2677bc1d7','ba594c7269cb95afc617093d2f04ecb8']"

  strings:
    $hex_string = { 7f 93 2a ed 70 da 61 a7 6d c5 78 82 78 92 2d e1 6a 8e 2c ec 3e 9f 6b ab 1e c2 30 be 3f ca 6e a2 3b 92 63 af 33 d9 43 a8 30 cd 43 da 33 88 28 d0 7b 84 35 b3 2f e7 0a c7 58 95 22 ef 7b e7 66 f1 }

  condition:
    filesize > 65536 and filesize < 262144
    and $hex_string
}