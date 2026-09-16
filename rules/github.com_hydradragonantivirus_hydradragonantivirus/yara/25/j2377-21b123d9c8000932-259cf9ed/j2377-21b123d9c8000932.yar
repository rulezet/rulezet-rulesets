rule j2377_21b123d9c8000932 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=j2377.21b123d9c8000932"
    cluster      = "j2377.21b123d9c8000932"
    cluster_size = "14"
    filetype     = "HTML document"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "html exploit iframe"
    md5_hashes   = "['21e7ab88a8b121604e96a3454106515f','25a3591eea2e5801577ed417e66f2ff7','f9d85041f8eed65e06eda075badde549']"

  strings:
    $hex_string = { 67 64 29 7b 78 7a 28 73 29 7d 3c 2f 73 63 72 69 70 74 3e 3c 21 2d 2d 2f 62 35 62 65 65 31 2d 2d 3e 0a 0a 3c 74 69 74 6c 65 3e d0 a0 d0 b5 d1 84 d0 b5 d1 80 d0 b0 d1 82 d1 8b 2c 20 d0 b3 d0 b4 }

  condition:
    filesize > 4096 and filesize < 16384
    and $hex_string
}