rule k2321_09245923d9eb1932 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k2321.09245923d9eb1932"
    cluster      = "k2321.09245923d9eb1932"
    cluster_size = "6"
    filetype     = "application/gzip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "vobfus conjar autorun"
    md5_hashes   = "['2a0de36eb91597d57834a3c617cd494b','5faa409d9dac8663e838c792a34a1aa5','f67dd874b22d3bd75dfff982c39e51b9']"

  strings:
    $hex_string = { 21 aa 81 7c b7 28 16 db 9f c9 c2 22 ac 91 36 55 47 26 cc f7 b9 bf 8d 44 7a 27 84 00 d9 b6 37 61 ec 1f 34 77 d9 f6 e3 d6 82 a7 c5 dc a1 6b a6 3d 87 46 65 77 92 c0 5f 11 39 d5 4c 4b b0 a2 e4 1a }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}