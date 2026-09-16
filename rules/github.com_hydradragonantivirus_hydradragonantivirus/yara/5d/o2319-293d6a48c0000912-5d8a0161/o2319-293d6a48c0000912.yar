rule o2319_293d6a48c0000912 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=o2319.293d6a48c0000912"
    cluster         = "o2319.293d6a48c0000912"
    cluster_size    = "4"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180911"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "cryxos coinminer miner"
    md5_hashes      = "['8632796cf8331a1392fde681cc66a53563d17bfe','ca89af0bc1f3cca0bfecdc40b878d7d143d09546','9b58380134250c98209bad1d6399644e71a4c1fa']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=o2319.293d6a48c0000912"

  strings:
    $hex_string = "{path}\" />',flash_markup:'<object classid=\"clsid:D27CDB6E-AE6D-1"

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}