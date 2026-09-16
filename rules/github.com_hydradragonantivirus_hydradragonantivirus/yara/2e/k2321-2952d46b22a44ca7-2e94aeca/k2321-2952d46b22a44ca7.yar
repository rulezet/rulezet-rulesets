rule k2321_2952d46b22a44ca7 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k2321.2952d46b22a44ca7"
    cluster      = "k2321.2952d46b22a44ca7"
    cluster_size = "8"
    filetype     = "PE32 executable (DLL) (GUI) Intel 80386"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "graftor nitol ddos"
    md5_hashes   = "['05b4a1058acf2351a7112fe2c21df23b','072ae8c812896227af90396fb4f14d82','e128b386a7b46d430cb1863b7b9b8904']"

  strings:
    $hex_string = { 6a 84 e2 4d 40 eb f6 22 52 65 31 b9 50 bc 1e 1a fd 9b 5e 1d 38 ee 2a 0c a3 17 11 cd 4a 5f 42 77 a4 cf 78 c5 91 de 76 5c 93 2d 4f ff 5d 47 2a b6 b3 0b cc 27 8c 7c 32 9d d5 1c 3d ab a9 83 a5 2f }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}