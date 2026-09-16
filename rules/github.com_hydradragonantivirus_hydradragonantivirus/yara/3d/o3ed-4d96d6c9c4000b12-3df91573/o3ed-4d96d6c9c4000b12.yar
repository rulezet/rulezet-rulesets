rule o3ed_4d96d6c9c4000b12 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=o3ed.4d96d6c9c4000b12"
    cluster      = "o3ed.4d96d6c9c4000b12"
    cluster_size = "731"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171123"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "ramnit nimnul bauhiz"
    md5_hashes   = "['000953b60e4c78478f46c9ce740e96bb','0042dcbbe966d8711044efb7b8b12c45','0cafae0d6680bf365216a9a4472a4a11']"

  strings:
    $hex_string = { c8 ff eb 1b eb 17 d9 45 fc dc 1d d0 3d 10 10 df e0 f6 c4 05 7a 07 b8 01 00 00 00 eb 02 33 c0 8b e5 5d c3 cc cc 55 8b ec 6a ff 68 22 fb 0f 10 64 a1 00 00 00 00 50 83 ec 54 56 57 51 8d 7d a0 b9 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}