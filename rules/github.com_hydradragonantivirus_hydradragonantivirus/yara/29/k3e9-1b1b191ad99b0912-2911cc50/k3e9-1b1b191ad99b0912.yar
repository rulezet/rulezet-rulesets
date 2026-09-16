rule k3e9_1b1b191ad99b0912 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e9.1b1b191ad99b0912"
    cluster      = "k3e9.1b1b191ad99b0912"
    cluster_size = "8"
    filetype     = "PE32 executable (GUI) Intel 80386"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171118"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "vbkrypt injector symmi"
    md5_hashes   = "['0da50f263e73e0f8b37bdd05b56cef68','22f257b7339ff0e91721563acbf88341','ce446553dacb09d9acaa630346f3c513']"

  strings:
    $hex_string = { 35 02 fc 86 eb 0f a3 65 7b 2b f1 39 4e 08 a9 66 56 83 d4 b4 e6 b9 83 17 0c 6c 72 6d b3 bc b6 3f d0 95 37 6e fe ce b0 5b cf 45 7f c1 96 a1 1b 52 b2 1c cd f3 7d 1e f8 63 dd 26 13 5d 42 bd 87 e3 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}