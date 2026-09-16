rule k2321_293c9cc1cc000912 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k2321.293c9cc1cc000912"
    cluster      = "k2321.293c9cc1cc000912"
    cluster_size = "4"
    filetype     = "application/gzip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171124"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "selfdel zbot generickd"
    md5_hashes   = "['4a4938558b0f73c336e3a431e5272656','8c22fa41a78fcad9598978bc8f2f9b41','b9547313ecda335f09f058510f6fa96e']"

  strings:
    $hex_string = { a5 c7 ce 34 3e 4a b3 e0 57 cb 6f b6 c8 2c 0d a2 86 da 41 11 bd 3a 2e 95 d7 4b 04 97 3c b9 76 90 a7 b5 be e4 d1 0b 8e 8c 4f f0 b2 46 53 68 15 99 42 91 a8 70 9b 45 5d 2b e1 19 71 50 e2 5a d4 59 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}