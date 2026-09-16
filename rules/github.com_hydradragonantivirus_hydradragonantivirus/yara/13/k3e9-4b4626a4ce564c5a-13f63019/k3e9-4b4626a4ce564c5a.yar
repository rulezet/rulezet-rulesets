rule k3e9_4b4626a4ce564c5a {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e9.4b4626a4ce564c5a"
    cluster      = "k3e9.4b4626a4ce564c5a"
    cluster_size = "18"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171111"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "virut virtob malicious"
    md5_hashes   = "['020a20d6771465b2a83f34340c841ba9','0575a44cbc49c4f620b311d3c3f4fbb3','e1cd45ae66b39a90a5de27d4e95ed8be']"

  strings:
    $hex_string = { 03 d5 8b 6e 10 03 fd 89 06 89 5e 04 89 4e 08 89 56 0c 89 7e 10 5d 5b 5f 5e c2 08 00 cc cc cc cc 56 8b 74 24 10 85 f6 76 2b 8b 4c 24 08 8b 44 24 0c 41 83 c0 02 8a 50 01 88 51 ff 8a 10 88 11 8a }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}