rule n3ed_091fb0f9c92bdb32 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=n3ed.091fb0f9c92bdb32"
    cluster      = "n3ed.091fb0f9c92bdb32"
    cluster_size = "1825"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171122"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "ramnit nimnul bmnup"
    md5_hashes   = "['00432d6601073574aa6eca4c0eb35ce3','01976b8904423e523374a03cdeda1731','085decd8130e63b3d3ad10ad2ea064e3']"

  strings:
    $hex_string = { 3c 30 75 04 0b c9 eb 02 2b c8 8d 45 d0 50 ff 75 14 51 57 e8 68 6b 00 00 83 c4 10 3b c3 74 04 88 1e eb 58 8b 45 d4 48 39 45 e0 0f 9c c1 83 f8 fc 7c 2d 3b 45 14 7d 28 3a cb 74 0a 8a 07 47 84 c0 }

  condition:
    filesize > 262144 and filesize < 1048576
    and $hex_string
}