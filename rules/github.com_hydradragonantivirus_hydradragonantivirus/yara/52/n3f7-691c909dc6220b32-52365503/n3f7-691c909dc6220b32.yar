rule n3f7_691c909dc6220b32 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=n3f7.691c909dc6220b32"
    cluster      = "n3f7.691c909dc6220b32"
    cluster_size = "168"
    filetype     = "text/html"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171122"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "faceliker clicker html"
    md5_hashes   = "['00db48a487c3cb0e38af4ef3cbfbb96c','0212fd13cb637d59ba828eda0454760e','179dbe8864812abebafee72a7602e833']"

  strings:
    $hex_string = { 42 25 45 32 25 39 39 25 38 30 27 3e e7 95 91 e3 81 ae e5 b0 8f e5 b1 8b e3 81 ab e4 bd 8f e3 82 93 e3 81 a7 e3 82 8b e4 b8 89 e6 af 9b e7 8c ab 26 23 39 37 39 32 3b 3c 2f 61 3e 0a 3c 2f 6c 69 }

  condition:
    filesize > 262144 and filesize < 1048576
    and $hex_string
}