rule o26bb_0d9d3169c8800932 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=o26bb.0d9d3169c8800932"
    cluster         = "o26bb.0d9d3169c8800932"
    cluster_size    = "66"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "graftor malicious dangerousobject"
    md5_hashes      = "['716d02c8142719285f81bd1a74edf4bd1e30d4ed','f95b09b2de77c82d4f17a57bc04138172ba26779','6214c41cda6a9070ca97262affe754c2d49a6bc0']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=o26bb.0d9d3169c8800932"

  strings:
    $hex_string = { ab 72 05 83 fb ff 77 a4 5f b8 cd cc cc cc 4e f7 e3 c1 ea 03 8a c2 c0 e0 02 8d 0c 10 02 c9 2a d9 80 c3 30 88 1e 8b da 85 db 75 de 8b c6 5e 5b 8b e5 5d c3 cc 55 8b ec 6a ff 68 40 47 52 00 64 a1 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}