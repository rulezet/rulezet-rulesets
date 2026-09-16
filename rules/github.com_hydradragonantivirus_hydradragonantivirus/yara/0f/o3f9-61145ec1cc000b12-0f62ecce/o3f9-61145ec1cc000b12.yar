rule o3f9_61145ec1cc000b12 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=o3f9.61145ec1cc000b12"
    cluster      = "o3f9.61145ec1cc000b12"
    cluster_size = "53"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "lyposit zusy ransom"
    md5_hashes   = "['046a7c5d32a7beecdb6f166a58012c87','06932b7688d31d71d9797be2a69d2cf3','95ae56da20fa9e9a35aa904570069fb6']"

  strings:
    $hex_string = { 65 f5 6b ba f3 52 10 f0 2a 85 f8 04 29 ca 61 4e e2 aa e9 88 cb 6a 12 58 ef 11 b8 3c da 3e f7 a6 b1 bf fd 7b 30 ff f9 b9 92 7d 73 71 fc 20 87 3d 74 45 3b 1f 53 5b 28 c6 b4 9e 69 1c 05 0e 25 9a }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}