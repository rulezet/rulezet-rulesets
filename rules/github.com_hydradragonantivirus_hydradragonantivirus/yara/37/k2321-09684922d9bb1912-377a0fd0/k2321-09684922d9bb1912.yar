rule k2321_09684922d9bb1912 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k2321.09684922d9bb1912"
    cluster      = "k2321.09684922d9bb1912"
    cluster_size = "4"
    filetype     = "application/gzip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = ""
    md5_hashes   = "['3dd65c829c701056b8c96384b48ada00','81ffd986a8c94d8e684565f2fb2d9807','c4e0e87f7a91c7f743f2205f1670367d']"

  strings:
    $hex_string = { 5a 2e f8 bd 7f 32 1c 76 10 84 c4 fb fd ab b5 31 4d 4b e7 9f 8f 88 cd d4 c7 90 df be 9e d2 f9 0d 23 f2 f4 61 12 35 af 13 7d 65 08 f6 00 66 7a e3 29 e0 94 6e a0 80 b6 1a e6 40 a7 a5 53 a1 9e 07 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}