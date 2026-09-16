rule j2321_2137528acd4f4b12 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=j2321.2137528acd4f4b12"
    cluster      = "j2321.2137528acd4f4b12"
    cluster_size = "10"
    filetype     = "PE32 executable (GUI) Intel 80386"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "upatre trojandownloader generickd"
    md5_hashes   = "['4c29e4005a5d73e8a20f3ec6af471042','631c09442e90f49a5e8c3eff73376c70','efb77efc433fc6d54c88f3b5869d3876']"

  strings:
    $hex_string = { 90 fd 8a 02 75 18 d0 67 29 4c 8f f7 ca ba 28 b5 dc 42 1e e1 e4 74 dc 48 3f 07 eb 66 93 4f 59 b0 22 b3 84 96 1d ac 68 3a 27 23 0c b9 5f 23 45 35 c5 e2 b9 81 67 d4 a9 11 60 ea f1 ec 70 f8 34 47 }

  condition:
    filesize > 4096 and filesize < 16384
    and $hex_string
}