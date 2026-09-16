rule o3e9_39997ec1cc000b32 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=o3e9.39997ec1cc000b32"
    cluster      = "o3e9.39997ec1cc000b32"
    cluster_size = "4"
    filetype     = ""
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171123"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "virlock nabucur malicious"
    md5_hashes   = "['a26146cba344d8c60b35fa33bb17958a','ad99f7bf25d156184899d35d530c559a','c681ed046117281de68cf81cddc34de2']"

  strings:
    $hex_string = { f3 cd ab ff f0 ca a9 ff ed c7 a8 ff e9 c3 a5 ff e6 c0 a3 ff e2 bc a1 ff de b8 9f ff da b4 9e ff d6 b1 9b ff d3 ad 99 ff cf aa 97 ff cc a6 96 ff c9 a4 94 ff b1 7f 73 ff 03 03 03 23 0b 0b 0b 0b }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}