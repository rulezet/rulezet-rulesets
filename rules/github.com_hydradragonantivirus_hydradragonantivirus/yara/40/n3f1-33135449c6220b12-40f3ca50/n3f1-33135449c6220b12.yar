rule n3f1_33135449c6220b12 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=n3f1.33135449c6220b12"
    cluster      = "n3f1.33135449c6220b12"
    cluster_size = "4"
    filetype     = "Zip archive data"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = ""
    md5_hashes   = "['46b9b75bb124e8e4686d8295e2992479','90dac3e8dca4c3a024f6736ef2242c64','d7d848035be54407fdd7c790e32ba5ae']"

  strings:
    $hex_string = { a2 47 2e 1c 6a ca 8f 43 24 26 99 4f 4a 87 03 da 56 b0 a5 69 7d af 0f 2f ae 38 d2 62 70 49 97 fb 8c 9f 5c 5c 58 40 d0 eb 4d 76 bf c1 39 33 91 f1 59 cb ea df d3 f9 30 7e c6 31 72 66 92 bd bc 4c }

  condition:
    filesize > 262144 and filesize < 1048576
    and $hex_string
}