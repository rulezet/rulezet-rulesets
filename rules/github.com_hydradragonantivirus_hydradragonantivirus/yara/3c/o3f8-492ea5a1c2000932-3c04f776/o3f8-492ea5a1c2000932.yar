rule o3f8_492ea5a1c2000932 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=o3f8.492ea5a1c2000932"
    cluster         = "o3f8.492ea5a1c2000932"
    cluster_size    = "514"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180909"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "fakeapp scamapp androidos"
    md5_hashes      = "['8b5daccc028515bf7838e6ebea3cc31857db1f4e','7db27877af08cb5f0b771f2adf0634cba6585452','02570c150aa5732ee7ff12a07cb25e117e87bcfb']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=o3f8.492ea5a1c2000932"

  strings:
    $hex_string = { 74 4a 65 6c 6c 79 62 65 61 6e 4d 72 31 2e 6a 61 76 61 00 10 48 43 56 69 65 77 43 6f 6d 70 61 74 49 6d 70 6c 00 12 48 45 42 52 5f 53 43 52 49 50 54 5f 53 55 42 54 41 47 00 06 48 49 44 44 45 4e }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}