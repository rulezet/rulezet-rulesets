rule j26bf_18966cccc2230b30 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=j26bf.18966cccc2230b30"
    cluster         = "j26bf.18966cccc2230b30"
    cluster_size    = "4"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "dotdo genx malicious"
    md5_hashes      = "['2b3b891e03eec825e13311164c1a439421d3d76c','6db3ceab21dbe1214b340029950d4442e3cbddf0','b0689c4699c524eade6ffe8577405229f11de912']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=j26bf.18966cccc2230b30"

  strings:
    $hex_string = { 79 46 69 6c 65 56 65 72 73 69 6f 6e 41 74 74 72 69 62 75 74 65 00 4e 65 75 74 72 61 6c 52 65 73 6f 75 72 63 65 73 4c 61 6e 67 75 61 67 65 41 74 74 72 69 62 75 74 65 00 53 79 73 74 65 6d 2e 44 }

  condition:
    filesize > 4096 and filesize < 16384
    and $hex_string
}