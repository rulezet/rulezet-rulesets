rule j3f0_291ee5acdee30b32 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=j3f0.291ee5acdee30b32"
    cluster      = "j3f0.291ee5acdee30b32"
    cluster_size = "13"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171118"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "graftor malicious malob"
    md5_hashes   = "['24da1b296ddd90c3fdcc1cf00cd26dba','38f61a00a86fcde3c63c106dc7e9899c','fd379768033c7b3daedbfd92cef855d4']"

  strings:
    $hex_string = { a8 04 f3 1f bd 58 05 1b df 85 50 49 53 02 d0 36 74 5c 04 bf 37 15 b9 8b d2 04 af 9a 14 ff d2 2e 21 06 fb 1a e4 62 0c ff d2 ae b0 b8 b8 68 80 20 b5 38 82 00 bd 01 e0 0b 7a 89 da 70 19 08 10 5f }

  condition:
    filesize > 4096 and filesize < 16384
    and $hex_string
}