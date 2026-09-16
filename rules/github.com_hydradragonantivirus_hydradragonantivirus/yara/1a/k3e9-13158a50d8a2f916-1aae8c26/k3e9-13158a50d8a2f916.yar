rule k3e9_13158a50d8a2f916 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e9.13158a50d8a2f916"
    cluster      = "k3e9.13158a50d8a2f916"
    cluster_size = "4"
    filetype     = "PE32 executable (GUI) Intel 80386"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = ""
    md5_hashes   = "['5c1a911815a0c700b4138d39c2730b98','758b52223b9623835ec98865f222d6ca','ce1604bf115ae58791300685fee040b2']"

  strings:
    $hex_string = { 64 9d 62 5d 89 6b 96 c0 2c 78 e6 0e 55 c9 6d 56 b2 c8 a5 ee a4 84 19 b5 66 f6 75 26 42 27 98 49 99 80 50 1a ed c4 27 07 08 0f 94 12 6c 14 73 bf 10 f1 52 32 35 85 d6 97 49 eb 9a f9 38 00 65 df }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}