rule o3f8_493905a0c6000b32 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=o3f8.493905a0c6000b32"
    cluster         = "o3f8.493905a0c6000b32"
    cluster_size    = "5"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180909"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "androidos dnotua risktool"
    md5_hashes      = "['2a7d3e91b98cd8eac245954f105d982098225ae0','48c5c152273276d87377ec86fd57d8fafcd7fe7e','e1ba0a9f8db9a2dc431e2662434292d75ba0ee2a']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=o3f8.493905a0c6000b32"

  strings:
    $hex_string = { 90 c3 85 c2 ad c2 84 37 40 c3 8f c3 a2 58 72 c3 bd 4e 49 42 34 09 02 03 01 c0 80 01 c2 a3 50 30 4e 30 1d 06 03 55 1d 0e 04 16 04 14 7a c3 b4 7e 3d 21 4a c2 87 2f 58 26 48 2a 67 3a c3 87 18 43 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}