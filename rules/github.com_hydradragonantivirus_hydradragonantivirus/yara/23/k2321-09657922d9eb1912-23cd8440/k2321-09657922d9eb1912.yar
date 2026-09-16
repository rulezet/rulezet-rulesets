rule k2321_09657922d9eb1912 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k2321.09657922d9eb1912"
    cluster      = "k2321.09657922d9eb1912"
    cluster_size = "9"
    filetype     = "PE32 executable (GUI) Intel 80386"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "vobfus conjar autorun"
    md5_hashes   = "['093458307346fe898bf807ee8872ea1c','3b6318badc03d410dcfc57f2679b5b05','df275826f2e22e0f573d04294634416d']"

  strings:
    $hex_string = { 5a b5 62 0c 67 48 85 32 88 71 b3 36 c6 02 1a 23 7a c8 bc 6b de ae f6 27 8a 72 55 d5 02 db ef d9 26 0b f6 4a 49 ad 15 c4 c2 a6 25 2b 43 ff fb f1 89 4d 81 fe f7 e5 f9 a4 13 dd 68 a8 f0 e4 c5 aa }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}