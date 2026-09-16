rule k3e9_1b1c68989ba10b16 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e9.1b1c68989ba10b16"
    cluster      = "k3e9.1b1c68989ba10b16"
    cluster_size = "9"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171118"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "neshta hllp malicious"
    md5_hashes   = "['02e950c07bd3ca4f44b86907ff69ee17','1dc9eb68d2e5c6c1bac5ef748dded959','fbd11880ff7a24c9e5a09f9cf04ea84c']"

  strings:
    $hex_string = { 43 18 52 50 3b 50 20 7e 05 e8 73 e6 ff ff 58 59 87 48 1c 8b 50 18 8d 14 8a 59 5f b8 0d 00 00 00 38 27 74 14 89 3a 83 c2 04 f2 ae 75 0b 88 67 ff 80 3f 0a 75 eb 47 e2 e8 5f 5b c3 8b c0 57 51 52 }

  condition:
    filesize > 65536 and filesize < 262144
    and $hex_string
}