rule k3e9_17c1294bc6620912 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e9.17c1294bc6620912"
    cluster      = "k3e9.17c1294bc6620912"
    cluster_size = "6"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171123"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "virut virtob malicious"
    md5_hashes   = "['65b494c788cf6298f5fb93f507c44da9','bd1b8ec8ff787fafec26a89ce61169de','e6606e87b98ee102a9227e6cc3374eae']"

  strings:
    $hex_string = { 33 db 39 5d 18 74 23 8d 85 fc f7 ff ff 50 ff 15 d0 10 00 01 59 2b f8 57 8d 84 45 fc f7 ff ff 50 6a 01 ff 35 04 32 00 01 ff d6 39 1d f8 30 00 01 5f 5e 75 26 8b 45 1c f7 d8 1b c0 83 e0 10 83 c0 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}