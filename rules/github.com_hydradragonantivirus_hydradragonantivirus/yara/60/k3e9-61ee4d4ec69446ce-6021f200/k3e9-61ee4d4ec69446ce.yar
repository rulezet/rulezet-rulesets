rule k3e9_61ee4d4ec69446ce {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e9.61ee4d4ec69446ce"
    cluster      = "k3e9.61ee4d4ec69446ce"
    cluster_size = "4"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171111"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "virut virtob malicious"
    md5_hashes   = "['0fa9ee43e204f64d6261c21007e5e410','cadc3c6a821b11b89d6820228ef01be1','e8a6a300ee8770493bc60ac88370472c']"

  strings:
    $hex_string = { 0a ca 97 00 8f 40 27 0f c7 4d 30 17 8d 6e 4c 3e dd 6f 4e 41 eb 63 42 35 f0 72 50 43 f7 bc 79 58 ff a1 6c 52 fe 57 37 27 f8 64 41 31 f6 65 42 32 f2 3e 21 14 d8 3c 22 14 b1 45 26 1a 48 44 2b 22 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}