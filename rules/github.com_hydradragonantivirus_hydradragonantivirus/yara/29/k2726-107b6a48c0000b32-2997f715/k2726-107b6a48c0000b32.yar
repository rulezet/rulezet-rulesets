rule k2726_107b6a48c0000b32 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=k2726.107b6a48c0000b32"
    cluster         = "k2726.107b6a48c0000b32"
    cluster_size    = "89"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "patched generickd malicious"
    md5_hashes      = "['0eb43e45a0e2cfaaa4a178b14a3d9ab3dcbf4c7c','e5a6c06a02691786fbc838f88d91895cb488661d','d30abdc7d09f50c8b36dceb26567466e0fb6b7f0']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=k2726.107b6a48c0000b32"

  strings:
    $hex_string = { 65 10 02 74 52 a1 f0 45 ba 77 33 d2 eb 25 8b 48 0c 89 4c 95 bc 33 ff 8b 8f a0 45 ba 77 3b cb 74 07 39 01 75 03 89 51 18 83 c7 04 83 ff 40 72 e7 8b 00 42 3b c3 75 d7 68 00 00 03 00 53 68 d0 23 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}