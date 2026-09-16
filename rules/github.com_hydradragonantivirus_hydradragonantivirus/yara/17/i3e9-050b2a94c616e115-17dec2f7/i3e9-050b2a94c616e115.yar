rule i3e9_050b2a94c616e115 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=i3e9.050b2a94c616e115"
    cluster      = "i3e9.050b2a94c616e115"
    cluster_size = "107813"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171122"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "upatre razy waski"
    md5_hashes   = "['00009fa86f08ffb0e9ae9b0f62d53d27','0002648e512a1c99d7010480ea51cc17','00182fcfdfd2c865b152a686b4ad6224']"

  strings:
    $hex_string = { b2 46 4c c5 50 d0 44 c4 f1 f0 0b 43 e0 3b e7 64 05 2a 14 cb 19 18 85 7a 38 b1 0d 51 02 69 d8 dd c1 57 4f 5b b4 74 b0 5e 28 80 79 5a cd e5 94 b9 9a 9d 8f 3d 36 3e 87 da ff 5f f5 c8 8c be ee 32 }

  condition:
    filesize > 262144 and filesize < 1048576
    and $hex_string
}