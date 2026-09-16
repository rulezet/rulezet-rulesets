rule k3e9_09b50a18963b0912 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e9.09b50a18963b0912"
    cluster      = "k3e9.09b50a18963b0912"
    cluster_size = "226064"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171122"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "dinwod malicious trojandropper"
    md5_hashes   = "['000036cb4c634c2ae24f30758ec0468f','00011410620e28a2181d92be1a3e9668','000a6b46cc667d7d099133f5829acb28']"

  strings:
    $hex_string = { ce e7 1c ae 6e e0 bf 8a f5 fb 86 7f fa 46 28 bd ea f8 3c 71 31 a2 c3 7c bc e4 92 f1 c6 52 17 b5 33 aa c5 53 e9 42 65 13 6f ca c8 9e a0 32 0f 38 0c 5e 9c ed 21 87 aa 55 c2 b0 73 5b 08 81 c1 8d }

  condition:
    filesize > 65536 and filesize < 262144
    and $hex_string
}