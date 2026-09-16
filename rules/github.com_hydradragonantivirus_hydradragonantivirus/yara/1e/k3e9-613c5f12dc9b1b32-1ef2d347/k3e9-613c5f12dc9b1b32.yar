rule k3e9_613c5f12dc9b1b32 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e9.613c5f12dc9b1b32"
    cluster      = "k3e9.613c5f12dc9b1b32"
    cluster_size = "4"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171118"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "virut virtob virux"
    md5_hashes   = "['46599dc4a8ab3e2277609351077ff764','6850052b7bdf9fb5c7f407d1feebd287','c597a719926e4bca27cafc73e76b47dc']"

  strings:
    $hex_string = { 8d 4a 0c 89 48 08 89 41 04 83 64 9e 44 00 33 ff 47 89 bc 9e c4 00 00 00 8a 46 43 8a c8 fe c1 84 c0 8b 45 08 88 4e 43 75 03 09 78 04 ba 00 00 00 80 8b cb d3 ea f7 d2 21 50 08 8b c3 5f 5e 5b c9 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}