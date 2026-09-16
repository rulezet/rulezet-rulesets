rule j3e9_519dce6390c30b16 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=j3e9.519dce6390c30b16"
    cluster      = "j3e9.519dce6390c30b16"
    cluster_size = "3"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171111"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "malicious buzus gnrx"
    md5_hashes   = "['18a6d58f6874ba311f261d7fd8be1c2e','32c5c6e2474ff4a16ded056809536af9','b9d666e0837f002b634f3b8956b4da1e']"

  strings:
    $hex_string = { 75 86 75 7b fe 73 05 82 00 00 04 06 72 76 06 03 01 f6 05 7a 8b 85 07 f4 7c 7e 74 0b 7f f3 0d b5 07 c9 73 89 0e f2 87 fa 01 7d f3 73 f7 77 86 7a 0c 01 70 87 f1 02 80 f7 f3 77 fb 7d fc 0f 05 f4 }

  condition:
    filesize > 4096 and filesize < 16384
    and $hex_string
}