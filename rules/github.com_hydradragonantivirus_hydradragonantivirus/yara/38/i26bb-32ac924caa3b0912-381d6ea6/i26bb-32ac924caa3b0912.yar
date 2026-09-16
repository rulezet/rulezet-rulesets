rule i26bb_32ac924caa3b0912 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=i26bb.32ac924caa3b0912"
    cluster         = "i26bb.32ac924caa3b0912"
    cluster_size    = "2257"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "generickd highconfidence malicious"
    md5_hashes      = "['07b91fc5cdfcd321f2b98e55cdee4a490c2ad1f9','6c951db6e2b7783fef7242c9391e445071652e62','cba08e87e2bbf2eb7386ca90be53baa21d9d0efa']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=i26bb.32ac924caa3b0912"

  strings:
    $hex_string = { c7 2b 59 42 12 d8 2d 60 1a 0e 8f d6 5c 15 85 82 e8 00 a4 89 dc 43 fa db 20 40 69 36 f1 5b 37 fd f9 9d e7 10 3c b3 e6 06 e2 51 34 54 90 6c 2f ec 7c ce 99 92 a5 a2 7c ec 68 c2 c8 96 04 a6 63 9a }

  condition:
    filesize > 4096 and filesize < 16384
    and $hex_string
}