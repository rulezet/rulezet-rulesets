rule n3fd_0852892c5ba30914 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=n3fd.0852892c5ba30914"
    cluster      = "n3fd.0852892c5ba30914"
    cluster_size = "1599"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171122"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "browsefox yontoo advml"
    md5_hashes   = "['00334babfa6cf98af08214a04eff9033','003473ae35d6258a4115f3b3a9fbbbca','02bd0b7fecb0f0472db12091ca8ad800']"

  strings:
    $hex_string = { 16 57 72 61 70 4e 6f 6e 45 78 63 65 70 74 69 6f 6e 54 68 72 6f 77 73 01 02 13 00 07 15 12 81 d9 01 1e 00 04 07 02 0e 08 05 00 00 12 80 f1 17 07 05 15 12 80 b1 01 0e 15 12 80 b1 01 0e 0e 11 10 }

  condition:
    filesize > 262144 and filesize < 1048576
    and $hex_string
}