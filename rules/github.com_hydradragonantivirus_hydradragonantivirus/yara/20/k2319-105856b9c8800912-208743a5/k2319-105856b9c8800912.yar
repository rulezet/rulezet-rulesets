rule k2319_105856b9c8800912 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=k2319.105856b9c8800912"
    cluster         = "k2319.105856b9c8800912"
    cluster_size    = "9"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "kryptik script diplugem"
    md5_hashes      = "['9a2c207d655c8d7676ddb94317d95f83ed5cacf6','0cc4517f4290986922ee6c8353f231eb913d14e4','67067682eb497627fca5c49ba2920e058b403e17']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=k2319.105856b9c8800912"

  strings:
    $hex_string = "M,Y,p){if(H[p]!==undefined){return H[p];}var P=((0x233,49.40E1)>"

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}