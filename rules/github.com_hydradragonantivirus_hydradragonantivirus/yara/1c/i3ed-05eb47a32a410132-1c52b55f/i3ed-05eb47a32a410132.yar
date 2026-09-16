rule i3ed_05eb47a32a410132 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=i3ed.05eb47a32a410132"
    cluster      = "i3ed.05eb47a32a410132"
    cluster_size = "34"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "bundpil gamarue zusy"
    md5_hashes   = "['07172e4d135cf2caad51553bbf68d984','0853016af15df18b70a27c58f44dae22','73c1bbbd3e976ada975c9ecf06dbdb2e']"

  strings:
    $hex_string = { 53 48 45 4c 4c 33 32 2e 64 6c 6c 00 5e 02 66 72 65 65 00 00 0f 01 5f 69 6e 69 74 74 65 72 6d 00 91 02 6d 61 6c 6c 6f 63 00 00 9d 00 5f 61 64 6a 75 73 74 5f 66 64 69 76 00 00 4d 53 56 43 52 54 }

  condition:
    filesize > 1024 and filesize < 4096
    and $hex_string
}