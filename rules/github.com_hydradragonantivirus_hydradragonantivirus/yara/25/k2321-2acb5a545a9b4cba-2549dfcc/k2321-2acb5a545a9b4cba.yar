rule k2321_2acb5a545a9b4cba {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k2321.2acb5a545a9b4cba"
    cluster      = "k2321.2acb5a545a9b4cba"
    cluster_size = "6"
    filetype     = "application/gzip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "tinba zusy backdoor"
    md5_hashes   = "['0741fa02668da9a0f26dc0153c93b129','11b508de4120a84803c52f678cb19c98','f89b3b5f8fbf42e60f3358b386217af1']"

  strings:
    $hex_string = { bf 9a 8f 1e 8b 17 70 2e 5f cc 44 e3 12 87 51 42 ad 78 1f e4 30 59 23 aa 75 a4 34 01 fe 41 86 f9 ee 8c 9f ed 35 0d 0f 3b 45 20 e8 ac 77 39 73 27 c3 62 83 b5 8e 7f 00 49 ef 2c 26 8e 53 b8 d8 46 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}