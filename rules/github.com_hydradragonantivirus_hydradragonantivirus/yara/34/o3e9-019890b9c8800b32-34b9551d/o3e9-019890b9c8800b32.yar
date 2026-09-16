rule o3e9_019890b9c8800b32 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=o3e9.019890b9c8800b32"
    cluster      = "o3e9.019890b9c8800b32"
    cluster_size = "10"
    filetype     = "PE32 executable (GUI) Intel 80386"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "backdoor cosmicduke miniduke"
    md5_hashes   = "['12042e38b51f9de455707f22caea29ac','71a9c04822c525c2af3e98e3c288c13f','e851c296f98775da1885431b7292e44f']"

  strings:
    $hex_string = { f5 81 76 f6 31 21 c0 60 01 e6 9d bc 29 b9 db 8b 7e 0e 12 8a 09 f4 88 17 26 b2 0c a0 fd 14 6d b7 8c 97 d8 f0 1f 4d 90 1c 48 6a 72 3b 6c b3 1b 58 74 0a ab 7c 55 c4 c2 ae 38 2a 45 7f 4f c8 37 ec }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}