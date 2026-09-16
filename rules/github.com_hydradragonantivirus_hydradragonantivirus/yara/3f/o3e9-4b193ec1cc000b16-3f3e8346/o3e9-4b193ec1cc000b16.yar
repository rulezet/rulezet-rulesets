rule o3e9_4b193ec1cc000b16 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=o3e9.4b193ec1cc000b16"
    cluster      = "o3e9.4b193ec1cc000b16"
    cluster_size = "8"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171123"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "virlock nabucur malicious"
    md5_hashes   = "['397a841a8b39b3583d3b748c1f9f3fad','451d81f7838c4e6a9175ee77dd6303eb','e6777510550a738cbc69ebb4c50a5d52']"

  strings:
    $hex_string = { 02 fb fb f9 79 94 a8 f2 ff 08 38 f5 ff 32 5b fe ff 53 76 fe ff 73 8e fe ff 8b a3 f8 ff a4 b4 ec ff b6 bc df ff bc c6 d4 ff af d7 ca ff 8e dc be ff 4a d2 9c ff 0f bc 79 ff 00 a7 6b ff 03 98 68 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}