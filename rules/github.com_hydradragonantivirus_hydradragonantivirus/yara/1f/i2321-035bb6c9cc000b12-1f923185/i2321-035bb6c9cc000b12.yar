rule i2321_035bb6c9cc000b12 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=i2321.035bb6c9cc000b12"
    cluster      = "i2321.035bb6c9cc000b12"
    cluster_size = "10"
    filetype     = "application/gzip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171118"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "cosmicduke backdoor razy"
    md5_hashes   = "['16b86734180ee5022ba13af7c2d04fa6','29d8d7ecd2cb898ccef770928f86825b','e83eac6e2bdce4e541bf1a267a624812']"

  strings:
    $hex_string = { b7 96 df 6f ee 68 3d 16 5b f5 14 a7 da 8d b2 ca 0f 9d de a8 dd bb f2 d4 e9 cb b9 d8 49 bc bd b6 61 e9 bd ea e4 54 29 b6 da 51 ac 3e 1e bf 74 67 43 f5 5a ec ae 1a eb 5d 4a fa 42 cc 2e af 2d 8e }

  condition:
    filesize > 1024 and filesize < 4096
    and $hex_string
}