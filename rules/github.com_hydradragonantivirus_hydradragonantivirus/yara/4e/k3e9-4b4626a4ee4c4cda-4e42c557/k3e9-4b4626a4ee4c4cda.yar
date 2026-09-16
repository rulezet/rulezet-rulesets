rule k3e9_4b4626a4ee4c4cda {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e9.4b4626a4ee4c4cda"
    cluster      = "k3e9.4b4626a4ee4c4cda"
    cluster_size = "9"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171111"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "virut virtob malicious"
    md5_hashes   = "['264d9cd4c58a44e7a447a8204cba8a53','51deaddd2b0eba115dd3dca45730eaef','ffb324712666d8eeacd2bea9e56409f8']"

  strings:
    $hex_string = { 0c 03 d5 8b 6e 10 03 fd 89 06 89 5e 04 89 4e 08 89 56 0c 89 7e 10 5d 5b 5f 5e c2 08 00 cc cc cc cc 56 8b 74 24 10 85 f6 76 2b 8b 4c 24 08 8b 44 24 0c 41 83 c0 02 8a 50 01 88 51 ff 8a 10 88 11 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}