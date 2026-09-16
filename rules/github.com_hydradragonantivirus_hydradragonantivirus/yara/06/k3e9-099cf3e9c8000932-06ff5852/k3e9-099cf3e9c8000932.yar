rule k3e9_099cf3e9c8000932 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e9.099cf3e9c8000932"
    cluster      = "k3e9.099cf3e9c8000932"
    cluster_size = "6"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171124"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "razy backdoor simbot"
    md5_hashes   = "['b0b6270c5a553f354e54e4e73d6f70ba','c2aae5f106074b531838b829f2f94ff7','effba014ca64250b1b3286fed6b1e147']"

  strings:
    $hex_string = { 47 01 8a 46 02 88 47 02 8b 45 08 5e 5f c9 c3 90 8d 74 31 fc 8d 7c 39 fc f7 c7 03 00 00 00 75 24 c1 e9 02 83 e2 03 83 f9 08 72 0d fd f3 a5 fc ff 24 95 30 68 40 00 8b ff f7 d9 ff 24 8d e0 67 40 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}