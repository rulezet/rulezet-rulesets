rule k3e9_4324d8549bbb1912 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e9.4324d8549bbb1912"
    cluster      = "k3e9.4324d8549bbb1912"
    cluster_size = "5"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "virut virtob virux"
    md5_hashes   = "['a5dd15c2355cc2460c75ea7d4ecd6a1c','b665ea090bcffac0dd4ee23d610e7218','e51b75e7397949f0186a720a5ada8cdb']"

  strings:
    $hex_string = { ac 01 47 65 74 53 74 61 72 74 75 70 49 6e 66 6f 41 00 4b 45 52 4e 45 4c 33 32 2e 64 6c 6c 00 00 7d 00 44 65 6c 61 79 4c 6f 61 64 46 61 69 6c 75 72 65 48 6f 6f 6b 00 00 ed 01 52 65 67 51 75 65 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}