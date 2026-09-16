rule k24c1_51b6329d96fb1932 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k24c1.51b6329d96fb1932"
    cluster      = "k24c1.51b6329d96fb1932"
    cluster_size = "11"
    filetype     = "Dalvik dex file version 035 (Zip archive data"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "androidos smssend trojansms"
    md5_hashes   = "['06ba8e2899833e7613d0b2ce87510c08','0b143dc624785baa078d3a03f6420687','d166a6d8857dae0a8358184fb4f3babb']"

  strings:
    $hex_string = { 0b 70 bc 3e 9c 47 94 1e b4 6f 53 31 eb ad c7 bf 61 33 e4 b8 a1 ed 26 64 c0 da e3 73 87 81 b1 a4 de e6 30 0a 16 8f 9e 6d ab 3a 7f 4d f7 05 39 b9 d0 4a 65 2d b1 f7 85 ea 9a f4 f3 fb d2 ca e8 82 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}