rule k3e9_592ec46b42220932 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e9.592ec46b42220932"
    cluster      = "k3e9.592ec46b42220932"
    cluster_size = "31"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171109"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "vbna chinky vobfus"
    md5_hashes   = "['253b505feac12b470e2076ff2d5b08ae','5332444cedf9c36f259e99ad453d7980','c5fae856c186a6cfcc3b1ae4ac6a0fb6']"

  strings:
    $hex_string = { 00 2f a4 fc 36 5a 00 88 fd 78 fd 68 fd 58 fd 48 fd 38 fd 28 fd 18 fd 08 fd f8 fc e8 fc d8 fc c8 fc b8 fc a8 fc 68 ff 58 ff 48 ff 38 ff 28 ff 18 ff 08 ff f8 fe e8 fe d8 fe c8 fe b8 fe a8 fe 98 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}