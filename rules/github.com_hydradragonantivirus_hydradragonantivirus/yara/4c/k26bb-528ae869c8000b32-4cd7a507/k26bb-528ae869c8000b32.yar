rule k26bb_528ae869c8000b32 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=k26bb.528ae869c8000b32"
    cluster         = "k26bb.528ae869c8000b32"
    cluster_size    = "9"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "virtob malicious virut"
    md5_hashes      = "['4763561f34f8fcaa4cc4449f839c66a65cd37038','fefae613c6018a9a20f64a1cf08dd5f7885009ad','143645edbda2e704edf6c26d02275ab728fb10ee']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=k26bb.528ae869c8000b32"

  strings:
    $hex_string = { 84 60 00 01 f7 d6 89 35 88 60 00 01 5e 5f 5b c9 c3 be 4f e6 40 bb eb e6 90 90 90 90 90 8b ff 55 8b ec 56 8b 75 08 33 c0 3b 75 0c 73 11 85 c0 75 0d 8b 0e 85 c9 74 02 ff d1 83 c6 04 eb ea 5e 5d }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}