rule k2321_2225293915bb489a {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k2321.2225293915bb489a"
    cluster      = "k2321.2225293915bb489a"
    cluster_size = "4"
    filetype     = "application/gzip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "dinwod trojandropper malob"
    md5_hashes   = "['2888e4cd77a0e0dce527d09d19a1fd81','8ee736afc259a9cc1bcbd55d770e0a9a','da4658a8413a932320eab2138e465c74']"

  strings:
    $hex_string = { 4b 7f 69 35 b3 07 87 ad 17 46 77 86 62 12 51 64 da ed 16 95 e0 ec c8 9a de 91 df b4 1d f2 3c f9 49 de 2a 33 c6 99 34 f6 5b 1a 23 38 d2 98 45 bd 96 d4 4e c4 c3 cb d8 8a d1 d7 48 a3 52 30 ee 2b }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}