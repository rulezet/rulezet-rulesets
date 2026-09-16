rule p3ed_111ba848c0000b12 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=p3ed.111ba848c0000b12"
    cluster      = "p3ed.111ba848c0000b12"
    cluster_size = "247"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171123"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "zusy ransom exploit"
    md5_hashes   = "['01028c9218d951c650168eed38b3e3d7','01763c071e2575c34d2803874206bd15','0a6f73fba0b669113ebec643dcf84970']"

  strings:
    $hex_string = { 6a de 38 8e fc 62 26 f4 0a 64 3e 3f db 6b 01 70 be 0e ba bb b9 68 90 34 c3 1a 6f b4 09 41 54 ac 61 ad 7a e9 a7 5c 86 e7 18 f1 ca d0 95 b3 c0 b6 80 0f 0c 69 ee f5 07 27 46 9b 77 fb cf 81 d3 9d }

  condition:
    filesize > 4194304 and filesize < 16777216
    and $hex_string
}