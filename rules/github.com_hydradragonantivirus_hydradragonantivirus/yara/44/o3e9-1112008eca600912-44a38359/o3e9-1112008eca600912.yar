rule o3e9_1112008eca600912 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=o3e9.1112008eca600912"
    cluster      = "o3e9.1112008eca600912"
    cluster_size = "4"
    filetype     = "PE32 executable (GUI) Intel 80386"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = ""
    md5_hashes   = "['297a30ccbd8ea25bd50fe493d827962d','4545ddadd4a45ab2c4f164db35d85ff3','f1b6fdd9c3905d4ccc7d68b96ba87ad9']"

  strings:
    $hex_string = { 5a b5 01 76 e4 10 4c 15 45 65 2b 78 7e 96 8b 9b 02 6d 3b 29 ed a5 a7 9d 4d 11 4a 99 61 bc 6a c9 af f5 2d 09 82 7f 7b 3d cc fd 86 2e 48 e2 3e 14 f4 ba da 22 75 e6 f2 71 b7 08 39 64 e1 cf c7 06 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}