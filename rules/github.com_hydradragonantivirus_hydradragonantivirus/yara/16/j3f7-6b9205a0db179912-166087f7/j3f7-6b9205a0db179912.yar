rule j3f7_6b9205a0db179912 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=j3f7.6b9205a0db179912"
    cluster      = "j3f7.6b9205a0db179912"
    cluster_size = "103"
    filetype     = "text/plain"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171118"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "derl hacktool rabased"
    md5_hashes   = "['0176f47ba32f2281ed4d807d89e7b07d','01d6042f2be8adb778c068bebbeafa65','3c4ecd1a98059d8bbb3b26c5ba5ded14']"

  strings:
    $hex_string = "ditor Version 5.00\r\n\r\n[HKEY_LOCAL_MACHINE\\SYSTEM\\Remote Manipula"

  condition:
    filesize > 4096 and filesize < 16384
    and $hex_string
}