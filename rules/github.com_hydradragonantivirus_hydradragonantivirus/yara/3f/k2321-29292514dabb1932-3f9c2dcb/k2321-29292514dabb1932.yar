rule k2321_29292514dabb1932 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k2321.29292514dabb1932"
    cluster      = "k2321.29292514dabb1932"
    cluster_size = "5"
    filetype     = "PE32 executable (GUI) Intel 80386"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "vobfus vbkrypt wbna"
    md5_hashes   = "['422020550bda2dc9de8b7bba125f1247','a8bb1c679b856b13f599eb8cea170c80','fbd45ba15db64f1799460384b5d251e2']"

  strings:
    $hex_string = { 27 97 18 c0 6e 4e 54 e3 cd 89 ea 1d e4 e6 c4 a6 f7 5b 9e 9d e9 5a ce 3d e2 5c 7c 0f de 4b 89 6c be da 9c ed dd 46 c5 96 71 58 4a 3e 65 b9 e1 21 3b 55 2e 13 cf ee 93 00 38 62 b2 ad 3f 8b 87 84 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}