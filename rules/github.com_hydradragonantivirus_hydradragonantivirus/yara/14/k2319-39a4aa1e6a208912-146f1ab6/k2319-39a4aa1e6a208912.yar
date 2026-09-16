rule k2319_39a4aa1e6a208912 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=k2319.39a4aa1e6a208912"
    cluster         = "k2319.39a4aa1e6a208912"
    cluster_size    = "3"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "multiplug kryptik diplugem"
    md5_hashes      = "['edc2936eea7ed24c02494406f45eec44aa2cbb7b','44996a173b40802f293f31ff30a486bcca03062f','a60e8d561baa0a465ce3ac81086251854ace36e7']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=k2319.39a4aa1e6a208912"

  strings:
    $hex_string = "g+A4+e0h7u.w2g)](s3);},_utf8_decode:function(H){var Y=\"L6\";var Q"

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}