rule o3e9_0b1359b65852e396 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=o3e9.0b1359b65852e396"
    cluster      = "o3e9.0b1359b65852e396"
    cluster_size = "840"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171109"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "installmonstr dlboost installmonster"
    md5_hashes   = "['0013265248ce80a6e8d2b861c068fc09','0047e6aa3e02c041ae996689325ba978','0657ad019a6f9248e2b145c02ce7fb62']"

  strings:
    $hex_string = { 7a cf 3a 47 8b 1b a1 eb 6e 47 55 af 92 01 04 71 04 d8 c0 77 1e 3a 15 23 67 47 7f 62 da c7 bc 6f b2 c0 d1 c0 38 09 39 4a 84 e1 8e 68 07 07 6d 08 51 43 d5 39 95 be f8 0f 89 32 02 94 f9 dd 87 e5 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}