rule j2321_11b231d6d5bb1932 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=j2321.11b231d6d5bb1932"
    cluster      = "j2321.11b231d6d5bb1932"
    cluster_size = "4"
    filetype     = "application/gzip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "upatre trojandownloader waski"
    md5_hashes   = "['12ed0990f21709e2182dc1a1065b97ab','416fa103ff272922e23a381fb97190ac','b3ef23d8302e48efa7f329cd43e1385d']"

  strings:
    $hex_string = { 9b b0 67 7e 72 79 93 9e 78 d5 db 5a 3d 0f 34 c9 30 26 68 ef 91 4b c2 1f 5d 88 12 b9 db d7 de c1 8b 06 8d df d2 ab 4d b3 02 6e 77 ce a9 04 05 89 2c 85 5e 9c 1e 45 af 18 f9 ba b8 f8 8c f6 fd 5b }

  condition:
    filesize > 4096 and filesize < 16384
    and $hex_string
}