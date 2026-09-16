rule k2321_1310cd72d7a30912 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k2321.1310cd72d7a30912"
    cluster      = "k2321.1310cd72d7a30912"
    cluster_size = "16"
    filetype     = "PE32 executable (console) Intel 80386"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "hupigon backdoor razy"
    md5_hashes   = "['04c5fe107a568fd1a3d060ad560e95e4','112a7f61ed182e4e2d244f15cd686acc','fffdec02bb6baac25ac7e7b2bb441ee7']"

  strings:
    $hex_string = { 97 9e 7f cf 6e 66 73 f5 c9 f1 37 a6 b6 2a 53 54 9f cd 44 dd e9 8e ad af ba 10 b3 79 88 48 60 b9 ed a3 26 d6 33 5c 7e 2f 99 dc 49 f9 68 d4 7c ec 05 0a 4c 03 14 a9 1c 96 94 71 31 19 52 d7 1b 90 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}