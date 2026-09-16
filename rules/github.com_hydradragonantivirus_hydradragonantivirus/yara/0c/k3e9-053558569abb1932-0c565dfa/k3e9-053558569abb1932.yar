rule k3e9_053558569abb1932 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e9.053558569abb1932"
    cluster      = "k3e9.053558569abb1932"
    cluster_size = "80"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "virut virtob sality"
    md5_hashes   = "['088fd209107de365edc7216af35b0fdf','0f4c5818b3f182e6245f281a8fe62738','67b7f900058171bc8dd62193f13ededd']"

  strings:
    $hex_string = { 36 ff d7 89 06 eb 32 3c 09 7c 0c 3c 0a 7e 27 3c 0d 74 23 3c 20 74 1f 57 ff 15 4c 51 00 01 3b f8 89 06 73 0a 8a 07 47 88 03 43 3b 3e 72 f6 8b 3e 8a 07 84 c0 75 d1 80 23 00 33 c0 5f 5e 5b c9 c2 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}