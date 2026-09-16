rule p3e9_519abcc9c4000b12 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=p3e9.519abcc9c4000b12"
    cluster      = "p3e9.519abcc9c4000b12"
    cluster_size = "86"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171123"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "virlock nabucur polyransom"
    md5_hashes   = "['006205e31ef5b67fd25b027ea84ab5e2','0602760f0603274efe33e9824cad3540','a9fbe55a04553a08bad5ce09fab4aa2f']"

  strings:
    $hex_string = { 80 00 00 03 80 00 00 03 c0 00 00 03 e0 00 00 03 e0 00 00 03 f0 00 00 03 f8 00 00 03 f8 00 00 07 f8 00 00 0f f8 00 00 1f f8 00 00 3f f8 00 00 7f 00 00 01 00 01 00 20 20 00 00 02 00 20 00 a8 10 }

  condition:
    filesize > 4194304 and filesize < 16777216
    and $hex_string
}