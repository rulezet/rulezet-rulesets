rule j3e7_7414d6a348000330 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=j3e7.7414d6a348000330"
    cluster      = "j3e7.7414d6a348000330"
    cluster_size = "40"
    filetype     = "application/octet-stream"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171123"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "shedun androidos piom"
    md5_hashes   = "['0c6ce81284f1b7fe9200d96e1e61da24','155125900196a62fd8100aac34d720fa','65a195038294cc85c9e1418d143889cd']"

  strings:
    $hex_string = { 67 2f 43 6c 61 73 73 3b 00 13 5b 4c 6a 61 76 61 2f 6c 61 6e 67 2f 4f 62 6a 65 63 74 3b 00 01 61 00 1a 61 6e 64 72 6f 69 64 2e 61 70 70 2e 41 63 74 69 76 69 74 79 54 68 72 65 61 64 00 26 61 6e }

  condition:
    filesize > 4096 and filesize < 16384
    and $hex_string
}