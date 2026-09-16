rule k3e9_4c9c824ec5a30b12 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e9.4c9c824ec5a30b12"
    cluster      = "k3e9.4c9c824ec5a30b12"
    cluster_size = "548"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171109"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "vbna vobfus chinky"
    md5_hashes   = "['0113fddcdfe9f8e181d526fe341a5e12','025853a478423b9c4c2dfda75dff4e04','1352cd56167f14656fbb9b9d0f589685']"

  strings:
    $hex_string = { 00 00 00 00 10 00 80 08 04 3c f7 94 08 00 d0 01 94 08 00 34 00 5e 08 00 0c 00 71 18 f7 04 3c f7 5a 6c 18 f7 cc 1c 70 06 00 64 f5 00 00 00 00 f5 02 00 00 00 04 3c f7 fe 8e 01 00 00 00 10 00 80 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}