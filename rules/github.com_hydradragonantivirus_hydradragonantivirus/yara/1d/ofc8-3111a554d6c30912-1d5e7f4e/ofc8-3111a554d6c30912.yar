rule ofc8_3111a554d6c30912 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=ofc8.3111a554d6c30912"
    cluster         = "ofc8.3111a554d6c30912"
    cluster_size    = "44"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180909"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "smspay riskware shedun"
    md5_hashes      = "['c84b80b7027f83f3da1f3a222044fc1113db8586','6e9cf1279fef19f40545c7f333f8b4a16375d4d6','52f34c192460344f8c169e86097e456878ef499b']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=ofc8.3111a554d6c30912"

  strings:
    $hex_string = { 1f ad f7 31 4d 78 ce 6a c6 fa 7a cd 45 16 d9 1c 52 f2 9c 5b a5 27 bc 19 bf b3 6f 12 49 75 94 1b 5d 50 40 65 10 a7 05 08 1e a1 99 00 0c 26 85 36 8d 03 90 d6 09 72 e8 db 86 d3 37 76 ba da 4e 02 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}