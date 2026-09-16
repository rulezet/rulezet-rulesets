rule n3f8_56da9499c2200b10 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=n3f8.56da9499c2200b10"
    cluster         = "n3f8.56da9499c2200b10"
    cluster_size    = "18"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "clicker androidos locker"
    md5_hashes      = "['823057d426f699b4b67ff1a4d9f887cd8de3b36f','1ecbb25ea5887b397c293d6144b3e20d0fe1d74e','a697f543a8ed583c2ac129fe11c596ddcb46de9c']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=n3f8.56da9499c2200b10"

  strings:
    $hex_string = { 62 24 31 3b 00 37 4c 61 6e 64 72 6f 69 64 2f 73 75 70 70 6f 72 74 2f 76 34 2f 77 69 64 67 65 74 2f 53 65 61 72 63 68 56 69 65 77 43 6f 6d 70 61 74 48 6f 6e 65 79 63 6f 6d 62 24 32 3b 00 51 4c }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}