rule k3e9_6a92979c51a31916 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e9.6a92979c51a31916"
    cluster      = "k3e9.6a92979c51a31916"
    cluster_size = "4566"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171122"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "vittalia malicious unwanted"
    md5_hashes   = "['00162c69f4273509f9847ca494043259','0035c6b6306c59a299b8eadf9edf3480','01af044c79227188e06b3be430a1d2a5']"

  strings:
    $hex_string = { 07 45 7e 4c e7 5f 4a db 7f 52 17 72 25 aa 42 8a f2 0c f2 12 fa df fb 08 fd 98 0e a4 88 32 0f 99 70 54 57 34 90 66 c4 16 e6 d4 d0 4f f5 b7 cf 56 15 cb a2 d9 28 ad d2 3c e5 31 b2 91 cd 27 4e 04 }

  condition:
    filesize > 262144 and filesize < 1048576
    and $hex_string
}