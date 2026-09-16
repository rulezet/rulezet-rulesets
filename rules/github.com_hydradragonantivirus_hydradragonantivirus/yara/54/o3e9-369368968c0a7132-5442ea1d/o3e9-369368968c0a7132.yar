rule o3e9_369368968c0a7132 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=o3e9.369368968c0a7132"
    cluster      = "o3e9.369368968c0a7132"
    cluster_size = "1279"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171109"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "installmonster installmonstr malicious"
    md5_hashes   = "['0001b6deed37c21a8bb83df117d832d9','003b12ea862a273afa22dcb9a00d375d','02e9cb72741d478f4c0e67bcca5e0a12']"

  strings:
    $hex_string = { 90 f4 7a ad 51 c4 49 8d 6b 86 fc cb ec 70 07 84 e5 3e 06 59 f6 b4 0d be 90 76 90 a8 ee bf 6d e5 12 50 65 99 db b2 9b 9c 08 22 cc 97 3e 9f 86 45 8c 2c 71 00 bd a1 82 d3 18 36 19 94 0d 32 85 27 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}