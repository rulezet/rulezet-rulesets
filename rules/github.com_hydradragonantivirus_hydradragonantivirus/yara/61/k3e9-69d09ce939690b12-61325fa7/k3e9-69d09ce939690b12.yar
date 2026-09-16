rule k3e9_69d09ce939690b12 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e9.69d09ce939690b12"
    cluster      = "k3e9.69d09ce939690b12"
    cluster_size = "186"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171118"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "mywebsearch toolbar malicious"
    md5_hashes   = "['003cc752334ac4415d35ad05c17d5e1c','008fee1ff1a608f8f6580c8f87bb81ef','1108e114ad03ce9c48f1fa479375acbf']"

  strings:
    $hex_string = { 9e 28 1f ba 7f 22 27 db 87 3b 42 9a 5c 2b 06 78 fa 83 0f e0 37 80 9c 21 76 ce 8e 38 6b ad ee 0a a2 a8 77 4f 92 c5 1d d5 c1 26 47 08 eb f6 d1 d2 97 68 94 6e 2d e4 bf f7 c3 bb a4 f0 82 e6 be 24 }

  condition:
    filesize > 262144 and filesize < 1048576
    and $hex_string
}