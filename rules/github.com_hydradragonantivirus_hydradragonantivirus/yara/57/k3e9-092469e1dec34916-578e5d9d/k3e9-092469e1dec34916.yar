rule k3e9_092469e1dec34916 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e9.092469e1dec34916"
    cluster      = "k3e9.092469e1dec34916"
    cluster_size = "15"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171123"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "installcore unwanted playturtle"
    md5_hashes   = "['1359c631e3012f35d126ab24a1acf050','17066b3248dd2dcc5be2ee0505bda180','ee8db38b0cf6f9618c62b5a641d1a066']"

  strings:
    $hex_string = { c8 13 12 31 f7 d9 8c 35 b6 bd 0a 3b 43 26 7a 23 f0 2b 59 11 a9 d2 5b 70 44 57 5a 4d 91 c5 6a cf 94 c4 ee fb b8 4c df 82 8f af 99 c3 6c 97 0c 09 d2 65 7f 03 a7 b0 58 6b cb 79 33 74 a5 41 f9 da }

  condition:
    filesize > 262144 and filesize < 1048576
    and $hex_string
}