rule o3e9_2db1da4c9d6d0cbe {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=o3e9.2db1da4c9d6d0cbe"
    cluster      = "o3e9.2db1da4c9d6d0cbe"
    cluster_size = "195"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171109"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "installmonster installmonstr malicious"
    md5_hashes   = "['0082a56be0ff140beb9e157c4c2ab288','0146d472f1cda5f34d8ad120c0efff0b','0d5ff143a5936422707675509659f939']"

  strings:
    $hex_string = { b7 0f 84 67 77 49 68 6b 1d fb 06 9e cf 47 de 33 49 c0 1c f7 99 23 99 b9 81 de 97 34 f9 df 0e 66 18 ca 11 15 bb 3f 50 21 62 27 02 5f 42 92 e5 81 05 23 64 4a d2 f1 48 29 43 60 0f c3 be 73 00 31 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}