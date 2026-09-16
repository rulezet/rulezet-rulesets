rule p3f0_4b24e448c0000916 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=p3f0.4b24e448c0000916"
    cluster      = "p3f0.4b24e448c0000916"
    cluster_size = "61"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "gamemodding heuristic malicious"
    md5_hashes   = "['0a28c368e8d98efe54ae426251ef0319','0b731cef49d7f9283e56b37b39b7d753','42cfe5117c67f587631732a1c91c0861']"

  strings:
    $hex_string = { b6 36 63 c8 0b 17 bc cf d2 00 80 3f 4b 57 f4 38 02 c1 01 6a 27 cb 13 52 c9 7f a5 41 89 b3 33 73 b2 be 8d 05 06 04 2b 62 4f 48 cc a9 31 e5 a1 dc 50 af 54 e1 5b c0 8c f8 fe 5e b4 82 6b 4e 6f 88 }

  condition:
    filesize > 4194304 and filesize < 16777216
    and $hex_string
}