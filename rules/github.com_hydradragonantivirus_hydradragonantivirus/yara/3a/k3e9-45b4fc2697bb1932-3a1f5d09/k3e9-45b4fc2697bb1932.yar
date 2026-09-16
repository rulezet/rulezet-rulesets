rule k3e9_45b4fc2697bb1932 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e9.45b4fc2697bb1932"
    cluster      = "k3e9.45b4fc2697bb1932"
    cluster_size = "5"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171111"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "virut virtob malicious"
    md5_hashes   = "['763266260e3c09e939b98fd9a9a86d11','78395bc5c168e18609e23fa2c0154f87','eec3f5506ccfea9c4a39e6eb184a9cef']"

  strings:
    $hex_string = { 74 12 8a 5e 01 8a d3 3a 59 01 75 0c 46 46 41 41 84 d2 75 e2 33 c9 eb 05 1b c9 83 d9 ff 85 c9 75 0c 8a 4f 04 8b 54 24 10 33 c0 40 88 0a 83 c7 08 8b 0f 80 39 00 75 b4 5e 5b 5f c2 04 00 81 3d f8 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}