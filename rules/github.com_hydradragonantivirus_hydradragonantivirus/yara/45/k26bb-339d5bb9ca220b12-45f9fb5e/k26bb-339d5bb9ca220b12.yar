rule k26bb_339d5bb9ca220b12 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=k26bb.339d5bb9ca220b12"
    cluster         = "k26bb.339d5bb9ca220b12"
    cluster_size    = "12"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "malicious virut attribute"
    md5_hashes      = "['21344edc6fddc241aeb091c60d8fb2ed91b48db4','2cd212c39f92ddc8a5546d049b991a209cd7c0b6','4ed39a9180cca1d48285ea720f44f724bf94fcf8']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=k26bb.339d5bb9ca220b12"

  strings:
    $hex_string = { b5 e5 32 8a 42 98 87 19 f7 12 b9 07 bf c0 1c 67 eb 85 7e fb 44 a9 e8 ae db 70 2c ec 54 af 5f 57 d9 f0 75 39 4d b3 ba 7f a4 0c 9e 3f 62 99 4b 9c b0 82 a8 63 4f bb 41 ac 4c 5d f8 02 c5 30 91 b7 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}