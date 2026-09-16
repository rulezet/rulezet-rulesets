rule p3f1_49193949c8000932 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=p3f1.49193949c8000932"
    cluster      = "p3f1.49193949c8000932"
    cluster_size = "607"
    filetype     = "application/zip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171123"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "smsreg riskware androidos"
    md5_hashes   = "['00d4e5b05f28c6f43a449f86e8eebb19','019869d66196ad4a0922b0a0bee5f94a','050c8ee9cddca36ab5da11fdd319de68']"

  strings:
    $hex_string = { 0e 12 98 27 f5 1e 22 83 f3 61 8f 96 7b 55 99 5f 0c 45 93 92 01 bd 3b 3f dc 88 19 aa 7c 8b 17 a8 b9 97 e4 48 95 ca 52 1c f7 d2 29 63 11 49 00 a7 e8 05 e1 ad ff 28 5b 8c be 60 2e b1 3e 8a ac ba }

  condition:
    filesize > 4194304 and filesize < 16777216
    and $hex_string
}