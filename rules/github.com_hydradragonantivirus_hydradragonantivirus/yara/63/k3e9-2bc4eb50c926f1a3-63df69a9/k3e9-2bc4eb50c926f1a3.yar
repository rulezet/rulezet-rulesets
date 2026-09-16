rule k3e9_2bc4eb50c926f1a3 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e9.2bc4eb50c926f1a3"
    cluster      = "k3e9.2bc4eb50c926f1a3"
    cluster_size = "8"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171109"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "ibryte installer optimum"
    md5_hashes   = "['28e53842e6993637b76fd4a4d96c26bb','2ff98c76f3b47d16c621f6f4d344f634','e5a477b7cf1929951bc584147387a424']"

  strings:
    $hex_string = { 2f 63 72 6c 2e 63 6f 6d 6f 64 6f 63 61 2e 63 6f 6d 2f 43 4f 4d 4f 44 4f 43 6f 64 65 53 69 67 6e 69 6e 67 43 41 32 2e 63 72 6c 30 72 06 08 2b 06 01 05 05 07 01 01 04 66 30 64 30 3c 06 08 2b 06 }

  condition:
    filesize > 65536 and filesize < 262144
    and $hex_string
}