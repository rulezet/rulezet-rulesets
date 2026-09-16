rule k3e9_42e2d6d1c8001116 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e9.42e2d6d1c8001116"
    cluster      = "k3e9.42e2d6d1c8001116"
    cluster_size = "59"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "virut virtob jxol"
    md5_hashes   = "['057eaa1e9298d2930b961c5e1228f5b4','52b06d885f421f6fc43b96b8cef030ce','b60a12f7f7e4fd2db5b1da9912345a04']"

  strings:
    $hex_string = { ec eb 26 f6 c1 01 74 17 ff 45 f8 84 c0 75 08 38 45 0b 88 45 0b 74 04 c6 45 0b 01 8b da eb 0a ff 45 f4 84 c0 75 03 89 55 f0 42 3b 55 14 72 bb 33 c0 40 39 45 f8 7f 08 75 37 83 7d fc 00 7e 0b c7 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}