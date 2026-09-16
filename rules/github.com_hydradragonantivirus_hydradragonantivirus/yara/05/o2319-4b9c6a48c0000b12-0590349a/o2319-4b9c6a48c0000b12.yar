rule o2319_4b9c6a48c0000b12 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=o2319.4b9c6a48c0000b12"
    cluster         = "o2319.4b9c6a48c0000b12"
    cluster_size    = "3"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180911"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "cryxos coinminer miner"
    md5_hashes      = "['4dc2e5a4382f0d8fa656bd86e4531c5eb306c82d','fc553f2a17f1e8bad5eaa2d6bcefbf0fdd238eea','f107ee2f54417af7ac969c3a1d4136d00dc0242c']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=o2319.4b9c6a48c0000b12"

  strings:
    $hex_string = "length}});var A,B=/^(?:\\s*(<[\\w\\W]+>)[^>]*|#([\\w-]*))$/,C=n.fn.i"

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}