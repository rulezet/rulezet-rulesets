rule o3e9_28b158728fa36d32 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=o3e9.28b158728fa36d32"
    cluster      = "o3e9.28b158728fa36d32"
    cluster_size = "235"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171109"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "installmonster installmonstr malicious"
    md5_hashes   = "['02ec4d7624f22734e038e87e3428e888','037b11f01f4f534ee99c1c939bc7e5ae','1bda36e3684f000fd5eb3592b9354b7c']"

  strings:
    $hex_string = { f8 56 18 d0 bc 13 bc 0c 2d a3 bc e6 12 9a 07 f1 ec 06 39 10 5b ff 68 d2 c2 7c 7f 12 94 aa 3a 55 17 b2 5c 53 09 68 08 f7 d7 39 02 4c 16 af 73 8e f4 a6 93 84 e4 7c 56 39 3b 39 30 93 f3 7b 57 8d }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}