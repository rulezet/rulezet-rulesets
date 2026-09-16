rule k3e9_2b16ed6d949b0912 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e9.2b16ed6d949b0912"
    cluster      = "k3e9.2b16ed6d949b0912"
    cluster_size = "6"
    filetype     = "PE32 executable (GUI) Intel 80386"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "tinba zusy emotet"
    md5_hashes   = "['19d26a13c7de9467ffba69efff1d40d7','1ad725a6cc0859eecb439d42a7ba7f56','f3239229063c9345db45814ed64c220b']"

  strings:
    $hex_string = { 79 b6 da 3a 57 63 9b a7 b5 95 ea 6c f3 75 f6 05 81 f6 b2 20 fb a2 60 c7 62 bd 73 89 a1 b1 dc d0 b4 2c a4 69 45 68 f3 ca b0 e6 d5 61 97 d6 44 34 af 8d bc b4 2e f2 d2 fa a8 4b 1b a3 2f 6f 8a b9 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}