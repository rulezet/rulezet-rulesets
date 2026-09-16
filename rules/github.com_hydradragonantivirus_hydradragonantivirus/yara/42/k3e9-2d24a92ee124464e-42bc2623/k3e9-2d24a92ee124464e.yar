rule k3e9_2d24a92ee124464e {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e9.2d24a92ee124464e"
    cluster      = "k3e9.2d24a92ee124464e"
    cluster_size = "3"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171111"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "virut virtob virux"
    md5_hashes   = "['2760b7b9027b66684e9fce4077411fce','3033d579a3a8f86956003ce6b30ddec0','3033d579a3a8f86956003ce6b30ddec0']"

  strings:
    $hex_string = { 56 fc 89 55 f8 8b 55 f4 f6 c2 01 89 5d 0c 75 74 c1 fa 04 4a 83 fa 3f 76 03 6a 3f 5a 8b 4b 04 3b 4b 08 75 42 83 fa 20 bb 00 00 00 80 73 19 8b ca d3 eb 8d 4c 02 04 f7 d3 21 5c b8 44 fe 09 75 23 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}