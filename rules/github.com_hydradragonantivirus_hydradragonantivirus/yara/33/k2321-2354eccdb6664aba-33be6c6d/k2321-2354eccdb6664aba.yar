rule k2321_2354eccdb6664aba {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k2321.2354eccdb6664aba"
    cluster      = "k2321.2354eccdb6664aba"
    cluster_size = "8"
    filetype     = "application/gzip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171118"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "tinba crypt emotet"
    md5_hashes   = "['0a5d21f1bb703dd5b756ba720c6d1515','17346221dc23a07f4590f6ab8189df93','bb2492f5878c9108222327b69746f7e1']"

  strings:
    $hex_string = { 8c 32 fd 98 81 90 3d 88 ef 2b ff 63 5d e9 8f c9 34 e5 ea 10 83 3c fc a7 cf e4 8a d3 b0 a1 7d 86 28 15 d2 8e 17 a3 bb 56 11 37 2e 2f 6f 44 6e 41 e6 94 19 29 45 53 26 c4 30 a6 e8 c3 52 ae 1f 1b }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}