rule j3ed_05393dd2d9e3d932 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=j3ed.05393dd2d9e3d932"
    cluster      = "j3ed.05393dd2d9e3d932"
    cluster_size = "23"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171118"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "malicious proxy ageneric"
    md5_hashes   = "['0bdde6b788d5d0303d4304c07ccf53a1','1f06e96ec90248337ee1cd11f0065453','c294741ddf73ca61a7dbd08a9c945981']"

  strings:
    $hex_string = { ac aa 40 ab 68 37 80 43 01 ff e2 51 49 68 10 68 10 00 4a 03 ea 83 c6 08 4e 83 c2 60 42 03 ec 2b e0 52 6a 00 6a 01 f7 d3 42 4f 00 13 01 6a 38 86 92 72 c2 cb 1d ea c2 04 1a 0d 91 0b 1f bb 50 26 }

  condition:
    filesize > 4096 and filesize < 16384
    and $hex_string
}