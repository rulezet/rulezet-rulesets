rule k26bb_093659e3dec34b16 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=k26bb.093659e3dec34b16"
    cluster         = "k26bb.093659e3dec34b16"
    cluster_size    = "130"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "installcore malicious unwanted"
    md5_hashes      = "['c36c9349697eccb6e7b5e7f56a2f971de986bbc8','599696039da14f1951a9b3d793b11997696a030b','11e126ec072e144355fd02b003d5581df0658b0e']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=k26bb.093659e3dec34b16"

  strings:
    $hex_string = { 40 ec 85 c0 75 de 5a eb 1b 8a 1a 8a 4e 06 eb e8 8a 5c 0e 06 32 1c 0a 80 e3 df 75 ed 49 75 f1 8b 06 5a 01 d0 5f 5e 5b c3 52 51 53 ff 50 f4 31 d2 8d 4c 24 10 64 8b 1a 89 19 89 69 08 c7 41 04 ed }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}