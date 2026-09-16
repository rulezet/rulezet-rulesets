rule o3e9_32b94be2d8bb1916 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=o3e9.32b94be2d8bb1916"
    cluster      = "o3e9.32b94be2d8bb1916"
    cluster_size = "9"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "cosmu mikey malicious"
    md5_hashes   = "['0470497e5dbb113b37941bdb723bf989','15bc0c3a91aa496c849791c6877a6de8','e61a6288f50965ccef96105fdde2595e']"

  strings:
    $hex_string = { 7c a8 a5 17 d0 4b c7 01 da c6 c4 bc 23 4a 72 27 4c dc ad b4 7a 7b 94 36 f4 a2 e1 d6 6e 91 93 70 9d b2 d8 a3 d2 9c 3f ac 64 5f fd 81 83 18 96 57 6f ee 60 03 00 3a cb 21 58 66 d1 bf 48 3d a9 bd }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}