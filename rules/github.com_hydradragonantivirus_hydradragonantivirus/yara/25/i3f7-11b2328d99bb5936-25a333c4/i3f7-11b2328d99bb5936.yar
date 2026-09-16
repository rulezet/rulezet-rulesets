rule i3f7_11b2328d99bb5936 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=i3f7.11b2328d99bb5936"
    cluster      = "i3f7.11b2328d99bb5936"
    cluster_size = "3"
    filetype     = "text/html"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171122"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "iframe html script"
    md5_hashes   = "['244c220d38227cd55b34d1c07e100fb7','2d1364115a7705cb317f145579fb654f','dff15e956273bbbab6d6d926c91e315c']"

  strings:
    $hex_string = { 68 2e 72 61 6e 64 6f 6d 28 29 2b 0d 0a 22 27 20 61 6c 74 3d 27 27 20 74 69 74 6c 65 3d 27 4c 69 76 65 49 6e 74 65 72 6e 65 74 3a 20 cf ee ea e0 e7 e0 ed ee 20 f7 e8 f1 eb ee 20 ef f0 ee f1 ec }

  condition:
    filesize > 1024 and filesize < 4096
    and $hex_string
}