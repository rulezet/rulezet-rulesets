rule o3e9_39b134469fa30b12 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=o3e9.39b134469fa30b12"
    cluster      = "o3e9.39b134469fa30b12"
    cluster_size = "11"
    filetype     = "PE32 executable (GUI) Intel 80386"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "installmonstr malicious unwanted"
    md5_hashes   = "['196c1b22b41338f6eb91aa8c7ef75536','38e3c2ad1cdca0c2928191d2868774fb','f2e0bbc824e2cc7555ff0d00d9ba0aab']"

  strings:
    $hex_string = { 52 ef f5 44 47 9d a1 fb ce d1 74 c6 e9 5a c0 1a c3 a2 65 b4 90 13 7e 41 b5 14 91 02 11 72 80 1e 38 e6 e8 de 28 5e e7 66 be 5c 24 a0 4e b8 d4 a9 22 67 5f c2 6e a4 bd 20 68 9b ba 45 19 f9 69 ec }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}