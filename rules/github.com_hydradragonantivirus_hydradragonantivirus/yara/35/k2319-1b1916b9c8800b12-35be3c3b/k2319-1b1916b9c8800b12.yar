rule k2319_1b1916b9c8800b12 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=k2319.1b1916b9c8800b12"
    cluster         = "k2319.1b1916b9c8800b12"
    cluster_size    = "6"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "kryptik script adinject"
    md5_hashes      = "['a840a13f78c486c4e32026bdc68f8339a4f220f8','0810204feda31af757c361d7ba67abf1c24078d2','171a19669bea6f43f128187be750d0b48f5f4507']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=k2319.1b1916b9c8800b12"

  strings:
    $hex_string = "?(0x149,119):(10.,27.3E1)))break};var B6y4={'Y1i':function(n,k){"

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}