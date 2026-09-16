rule k26bb_193e79e3dec34b16 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=k26bb.193e79e3dec34b16"
    cluster         = "k26bb.193e79e3dec34b16"
    cluster_size    = "1691"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "installcore dealply malicious"
    md5_hashes      = "['011a49eaec722c106491b3672cc6c00081f7b730','2814e377c4dff51d504aab82aac46d6f8fe40adf','5788aaa17a94cac3c5b05188a37ee42f4cb404a9']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=k26bb.193e79e3dec34b16"

  strings:
    $hex_string = { 61 20 69 73 20 63 6f 72 72 75 70 74 65 64 20 28 25 64 29 00 00 53 83 c4 f8 8b d8 89 1c 24 c6 44 24 04 0b 54 6a 00 b9 18 7e 40 00 b2 01 b8 c8 77 40 00 e8 ae da ff ff e8 a9 b0 ff ff 59 5a 5b c3 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}