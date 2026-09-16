rule k231b_0294e69ace210b12 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=k231b.0294e69ace210b12"
    cluster         = "k231b.0294e69ace210b12"
    cluster_size    = "13"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "faceliker likejack html"
    md5_hashes      = "['5f9c465b3aa0f2ff1260a58b6f5a1c4c55725dac','56a7ab98bcba96a91ab82ddd623f8ea61a86f372','5460afc7f1d8f8e78624fb83dc6f72eb4ce5844d']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=k231b.0294e69ace210b12"

  strings:
    $hex_string = { 67 65 28 27 68 74 74 70 3a 2f 2f 77 77 77 2e 72 61 66 69 73 74 2e 63 6f 6d 2f 27 29 3b 22 3e 47 69 72 69 c5 9f 20 53 61 79 66 61 6e c4 b1 7a 20 59 61 70 c4 b1 6e 3c 2f 61 3e 26 6e 62 73 70 0a }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}