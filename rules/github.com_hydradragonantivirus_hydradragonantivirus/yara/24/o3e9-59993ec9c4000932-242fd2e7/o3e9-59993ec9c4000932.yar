rule o3e9_59993ec9c4000932 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=o3e9.59993ec9c4000932"
    cluster      = "o3e9.59993ec9c4000932"
    cluster_size = "174"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171123"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "virlock krypt nabucur"
    md5_hashes   = "['025ac9236bfad48c7ef6261dea4f38f7','02793d34bca3d8552e0b9f5b4a2ddf9d','77b8a5560780aa3be8467bd1493b796c']"

  strings:
    $hex_string = { 00 fc fd fd 00 fd fc fd 00 f2 fb fa 00 22 d8 f7 00 05 dc fb 00 0a d5 f8 00 08 9c ef 00 1c 4f df 00 2a 2a d5 00 1d 21 cd 00 0e 51 da 00 26 a4 eb 00 75 9f c0 00 10 a1 de 00 4c c8 f2 00 f9 fb fa }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}