rule j3e9_61166826ca230b32 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=j3e9.61166826ca230b32"
    cluster      = "j3e9.61166826ca230b32"
    cluster_size = "35"
    filetype     = "PE32 executable (GUI) Intel 80386"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "heuristic corrupt corruptfile"
    md5_hashes   = "['0193940962e4ead405737c3952f6f694','036f4b9d264d658998a2372cd0d7d702','7a190811e9a274945107f17ee4c78700']"

  strings:
    $hex_string = { 40 ec 85 c0 75 de 5a eb 1b 8a 1a 8a 4e 06 eb e8 8a 5c 0e 06 32 1c 0a 80 e3 df 75 ed 49 75 f1 8b 06 5a 01 d0 5f 5e 5b c3 52 51 53 ff 50 f4 31 d2 8d 4c 24 10 64 8b 1a 89 19 89 69 08 c7 41 04 ed }

  condition:
    filesize > 4096 and filesize < 16384
    and $hex_string
}