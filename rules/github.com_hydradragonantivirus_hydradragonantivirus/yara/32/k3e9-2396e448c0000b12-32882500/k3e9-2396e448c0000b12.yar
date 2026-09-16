rule k3e9_2396e448c0000b12 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e9.2396e448c0000b12"
    cluster      = "k3e9.2396e448c0000b12"
    cluster_size = "8"
    filetype     = "PE32 executable (GUI) Intel 80386"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "nitol fdld dropped"
    md5_hashes   = "['0fc39a07bc630b51b74d7e52cca612f3','2fe7b1cd35e3d59216f3523dd4dff62d','d6907683c654eb1a4b239b4d44f3d85f']"

  strings:
    $hex_string = { 9d 16 84 8f 73 c2 9f 79 32 5e 51 bd f2 f1 3f f9 55 c7 7f 6c ac 43 e7 c0 95 45 d4 d9 04 46 fc ad 89 47 18 a4 7e 39 b2 42 58 69 8e 71 bb 2a 73 d6 cf 97 1f 86 f0 ad f3 e5 be bc 85 74 4a 2e 4e 76 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}