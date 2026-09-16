rule j3ec_43cca699c2200932 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=j3ec.43cca699c2200932"
    cluster      = "j3ec.43cca699c2200932"
    cluster_size = "496"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "fileinfector vhpli malicious"
    md5_hashes   = "['00998e19af8230fbe38451e7cda2b75f','010840a2630d20b08608dfcb37242022','0f44a119000ebcc431488e77432945d7']"

  strings:
    $hex_string = { 18 03 05 be 15 cd 5b 07 08 8b f1 81 c6 f8 d9 59 07 0b 8b f1 c1 e6 04 81 c6 45 9b 3c 07 07 02 03 8b 45 00 04 8b d5 8b 02 07 02 02 33 c6 05 8b f8 33 fe 97 09 02 03 89 45 00 06 8b fd 8b d0 89 17 }

  condition:
    filesize > 4096 and filesize < 16384
    and $hex_string
}