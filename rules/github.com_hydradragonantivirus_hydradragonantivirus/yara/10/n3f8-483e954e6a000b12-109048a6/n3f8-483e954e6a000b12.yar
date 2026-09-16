rule n3f8_483e954e6a000b12 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=n3f8.483e954e6a000b12"
    cluster      = "n3f8.483e954e6a000b12"
    cluster_size = "156"
    filetype     = "application/octet-stream"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "sandr androidos kasandra"
    md5_hashes   = "['02708f76ea5ed628cb713dff8b2376bd','03474954f1ca5d8e54f5c3b56ebba9a8','1d1de8d15e5d38a9881ca243ccadffa6']"

  strings:
    $hex_string = { fc ee 14 02 0a 88 f1 14 01 02 bc f4 14 01 02 d0 f5 14 01 02 94 f6 14 c0 16 00 84 f7 14 01 00 d8 8b 15 04 00 a8 8d 15 00 04 01 03 99 06 10 01 10 01 10 01 10 ca 16 81 80 04 8c 92 15 cb 16 01 b4 }

  condition:
    filesize > 262144 and filesize < 1048576
    and $hex_string
}