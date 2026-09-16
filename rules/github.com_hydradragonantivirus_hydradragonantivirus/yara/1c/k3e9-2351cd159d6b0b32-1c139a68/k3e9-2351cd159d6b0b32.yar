rule k3e9_2351cd159d6b0b32 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e9.2351cd159d6b0b32"
    cluster      = "k3e9.2351cd159d6b0b32"
    cluster_size = "385"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "zbot graftor delf"
    md5_hashes   = "['00b535f2142aac1c79fa9efd8b1cbd6d','00fdc77d72b66c34f0eabfec32ae7b96','0ab025086513ae8aac1b26ee014d34b1']"

  strings:
    $hex_string = { 48 fc 33 d5 52 50 8e c7 99 06 04 24 16 54 24 07 83 c4 0b 8a 55 f7 88 10 4a ff 4d ef 0f 85 74 ff ff 02 5f 5e 5e 8b e5 60 c3 8d 43 00 53 59 57 55 86 c4 f8 c1 38 b5 44 6a 0f ba f9 8b e2 81 c3 95 }

  condition:
    filesize > 16777216 and filesize < 67108864
    and $hex_string
}