rule o3e9_3498e448c4010b32 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=o3e9.3498e448c4010b32"
    cluster      = "o3e9.3498e448c4010b32"
    cluster_size = "743"
    filetype     = ""
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171123"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "virut virtob virux"
    md5_hashes   = "['000393cf50a8b038ee04958d8d026176','0072fc3b86efedd6f441848dfaf7462b','05cf753c4b61867896273f66482ff88c']"

  strings:
    $hex_string = { e7 e7 00 e4 f0 f0 00 b0 c4 c7 00 90 a9 ad 00 66 cc ff 00 66 99 cc 00 99 cc ff 00 c6 d6 ef 00 ff ff ff 00 fe fe fe 00 fc fc fc 00 f8 f8 f8 00 f1 f1 f1 00 ea ea ea 00 e3 e3 e3 00 dd dd dd 00 d7 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}