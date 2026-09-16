rule k3e7_48c4ea0100000000 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e7.48c4ea0100000000"
    cluster      = "k3e7.48c4ea0100000000"
    cluster_size = "73"
    filetype     = "application/octet-stream"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171123"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "metasploit androidos hacktool"
    md5_hashes   = "['020277f5f8788112a4c0dd462ce01d28','064d3e3994cbccc8c582d66c37592f5f','349da095c31bebb1c85562db8e85bfab']"

  strings:
    $hex_string = { 69 6f 6e 2e 42 4f 4f 54 5f 43 4f 4d 50 4c 45 54 45 44 00 06 61 70 70 65 6e 64 00 09 61 72 72 61 79 63 6f 70 79 00 01 62 00 01 63 00 12 63 68 65 63 6b 43 6c 69 65 6e 74 54 72 75 73 74 65 64 00 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}