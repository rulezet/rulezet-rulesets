rule k3e9_69d09ce915cf2312 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e9.69d09ce915cf2312"
    cluster      = "k3e9.69d09ce915cf2312"
    cluster_size = "398"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "malicious mindspark mywebsearch"
    md5_hashes   = "['0016ea4c6d6718448b5d3d2a63883023','00338fc42782b4e2a1d671284327c3f6','0b4a439ee3155bd69e2f52f6aef0c4af']"

  strings:
    $hex_string = { c6 1e 85 83 00 1b f4 71 e1 ba 0f e3 bf 2d 65 53 5e 98 58 fd ce a8 1f 03 f3 0b 5f 35 62 44 57 fe 82 bc 75 33 df 1d b5 e5 3e ae 6d d1 a6 7b f7 bd f1 eb b6 f2 27 7f 68 b8 ed e1 84 ee b7 2a 47 7d }

  condition:
    filesize > 262144 and filesize < 1048576
    and $hex_string
}