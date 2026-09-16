rule nfc8_211c96b9caa00b12 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=nfc8.211c96b9caa00b12"
    cluster         = "nfc8.211c96b9caa00b12"
    cluster_size    = "925"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "obfus banker androidos"
    md5_hashes      = "['083496f0221c7f925ad24d3281737cb448c5eb2f','be679ed093e2e6b2c9c865ed5bfb67a903712392','617b81d3346bcc0e6b38e97e28f7be1b9348f384']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=nfc8.211c96b9caa00b12"

  strings:
    $hex_string = { ce 2b 1a 5d af 78 93 57 5e eb 75 84 c7 d5 76 ad c5 da 6a a2 e1 61 a2 82 79 d9 dd be 9a dc f4 42 8c 74 8b a7 98 c0 5a 6e f0 94 0e c9 55 85 c1 48 81 32 30 bb d0 e6 5f ff 8f df c4 9e 1c 27 6f 49 }

  condition:
    filesize > 262144 and filesize < 1048576
    and $hex_string
}