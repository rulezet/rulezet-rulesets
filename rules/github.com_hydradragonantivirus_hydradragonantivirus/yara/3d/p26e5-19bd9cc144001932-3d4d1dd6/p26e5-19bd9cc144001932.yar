rule p26e5_19bd9cc144001932 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=p26e5.19bd9cc144001932"
    cluster         = "p26e5.19bd9cc144001932"
    cluster_size    = "5"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180909"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "razy malicious attribute"
    md5_hashes      = "['b695ad7a7c4f0539c3a476a03d3c88531a4cf834','906d96044045db10e42e80ed0d82d6879106ca56','47fe9b0b83a01d2b678b6c62db9fabcd5c682d0a']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=p26e5.19bd9cc144001932"

  strings:
    $hex_string = { 00 00 08 0a 4a 19 21 36 18 1e 45 18 5d 14 03 ec 14 54 d0 5d 58 ca 2f 2d 12 5f 0a fa 21 c7 2f 36 bc f8 6f c5 d8 c2 54 b9 1c 7b 54 1e 18 be 99 7b b4 28 f9 45 bb da 2f 07 40 a3 e5 cd 0e 0a 08 08 }

  condition:
    filesize > 4194304 and filesize < 16777216
    and $hex_string
}