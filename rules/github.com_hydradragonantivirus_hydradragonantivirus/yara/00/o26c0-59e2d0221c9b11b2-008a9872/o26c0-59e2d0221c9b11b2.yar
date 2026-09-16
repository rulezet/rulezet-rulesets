rule o26c0_59e2d0221c9b11b2 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=o26c0.59e2d0221c9b11b2"
    cluster         = "o26c0.59e2d0221c9b11b2"
    cluster_size    = "346"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180909"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "malicious prepscram attribute"
    md5_hashes      = "['043cf90dc88d8cf06dbe9b93cbd2399e80484dbf','f6ad49f3aee36bc715103acd71f2cc1ca99440b9','3aec77b9b9925485c2c1e54b17802859957ff6d7']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=o26c0.59e2d0221c9b11b2"

  strings:
    $hex_string = { 36 74 2d 67 d3 7c 5d 51 48 4b 88 55 3b d9 32 f5 22 ee d1 a6 15 49 89 be 0c da 04 b4 40 75 ec 6b 1f 1d 15 34 9a a2 af 19 7d e4 ab ed 6a 79 e2 8d 44 2b f8 86 2a 35 6e 9d bc 9e 63 5b 73 f7 b5 d5 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}