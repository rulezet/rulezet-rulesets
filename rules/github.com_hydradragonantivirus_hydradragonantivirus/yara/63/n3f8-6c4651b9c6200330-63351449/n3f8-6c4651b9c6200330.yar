rule n3f8_6c4651b9c6200330 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=n3f8.6c4651b9c6200330"
    cluster         = "n3f8.6c4651b9c6200330"
    cluster_size    = "17"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180911"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "androidos smsagent fakeinst"
    md5_hashes      = "['7c2a29244523a66ce212f2c0ed72cb74232d524a','870deca8baa11af4ae585c31aa08237dd4568e2e','1bc90dd6e9ce6afa93eaa5247063d3e39ddfb2ff']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=n3f8.6c4651b9c6200330"

  strings:
    $hex_string = { 64 62 61 63 6b 54 79 70 65 54 6f 53 74 72 69 6e 67 00 01 5b 00 15 6e 75 6d 62 65 72 4f 66 54 72 61 69 6c 69 6e 67 5a 65 72 6f 73 00 02 2c 20 00 0f 46 45 45 44 42 41 43 4b 5f 53 50 4f 4b 45 4e }

  condition:
    filesize > 262144 and filesize < 1048576
    and $hex_string
}