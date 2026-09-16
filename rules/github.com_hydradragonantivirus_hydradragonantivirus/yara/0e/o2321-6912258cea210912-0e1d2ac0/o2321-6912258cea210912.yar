rule o2321_6912258cea210912 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=o2321.6912258cea210912"
    cluster      = "o2321.6912258cea210912"
    cluster_size = "52"
    filetype     = "PE32 executable (GUI) Intel 80386 (stripped to external PDB)"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "filetour symmi feos"
    md5_hashes   = "['13bf905a4f52661ae9211447c17af190','148aa4a5a1d1f385da2d7298cb1200fa','5bbb3034a68d8c0c9f082b9d01bf03b7']"

  strings:
    $hex_string = { 70 93 d7 5d b6 55 1c 2f 61 4d 5a 7f cf f3 9b 0e 43 41 f0 74 78 1d 01 94 85 2b e1 28 44 0b 12 7d 18 06 56 ff 97 ab e3 fe 47 b7 ba 1f 96 66 9a d9 c9 13 3f 91 b8 cc b2 bd 0d da 04 77 49 99 fa a8 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}