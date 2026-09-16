rule k3e9_6a1eb949c8000b00 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e9.6a1eb949c8000b00"
    cluster      = "k3e9.6a1eb949c8000b00"
    cluster_size = "49"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171111"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "virut virtob vetor"
    md5_hashes   = "['43191f9cb41a2a8b3a88bd0c87c3ef85','4e86d4ea5baa138e596515da9885f19e','ee4f0851942b3365894d618c0db00b7e']"

  strings:
    $hex_string = { 71 d0 11 8b 1a 00 a0 c9 1b c9 0e fb be 3b 05 ba b3 d2 11 93 58 00 00 f8 75 ae 17 f8 8c c8 6e 1b a4 d2 11 93 49 00 00 f8 75 ae 17 81 1e 87 34 3a d3 d2 11 92 c7 00 c0 4f 68 d5 ae 9c 9f 79 97 69 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}