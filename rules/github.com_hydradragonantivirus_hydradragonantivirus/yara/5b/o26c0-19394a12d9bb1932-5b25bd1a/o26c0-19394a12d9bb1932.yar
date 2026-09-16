rule o26c0_19394a12d9bb1932 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=o26c0.19394a12d9bb1932"
    cluster         = "o26c0.19394a12d9bb1932"
    cluster_size    = "12"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180909"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "symmi malicious heuristic"
    md5_hashes      = "['eefa8eb960030cfa7bbd8ed1f4d0b356dfe9dfcd','83d5f74c8f9351bd1139425d978a353b7c05f2d5','8d1c60788d65f4ccc7ea01ab9644a0a5b572e0f9']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=o26c0.19394a12d9bb1932"

  strings:
    $hex_string = { fc 7f 50 fb 1d 3f 10 e0 6c 19 1f 85 7a ca 9b 93 f8 7d 80 53 4e 95 b3 06 78 5e 59 0f 27 55 18 6a 57 ae 00 17 4c c9 ef b8 6e ea 69 b5 f3 58 77 97 ce e2 bd ab 7e e1 ec 04 a4 c0 e4 d8 9f 52 5d 2a }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}