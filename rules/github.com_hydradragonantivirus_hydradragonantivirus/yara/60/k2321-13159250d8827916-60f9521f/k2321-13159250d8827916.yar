rule k2321_13159250d8827916 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k2321.13159250d8827916"
    cluster      = "k2321.13159250d8827916"
    cluster_size = "13"
    filetype     = "PE32 executable (GUI) Intel 80386"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171124"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "regrun ludbaruma rontokbro"
    md5_hashes   = "['10c32748c93c7d7eed5221a7258ecd20','1745bbca9200091fc6ef5c986097678f','e88d9596fdfd60102c228bded2bbf325']"

  strings:
    $hex_string = { 78 0d 27 60 68 f9 3b d8 b2 92 16 44 60 df e1 9b 2f dc fb f6 f5 a2 95 8f 5e 58 3a 67 e5 c3 17 96 4e e3 52 10 2d 7d 84 4b 70 a6 81 a5 43 56 c7 18 ed db e9 22 46 cd 3b 1d 63 d4 b1 d3 f1 38 3f bf }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}