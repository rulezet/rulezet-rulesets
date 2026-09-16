rule k2321_0b15698986220b12 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k2321.0b15698986220b12"
    cluster      = "k2321.0b15698986220b12"
    cluster_size = "18"
    filetype     = "application/gzip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "brontok email backdoor"
    md5_hashes   = "['14c8899ad03c65349862f9a1b949a505','16bff25d08465984e32dad1229db35fa','e36a31a28aa30bc8612694d43ace58e6']"

  strings:
    $hex_string = { 30 9b 29 7e 79 f3 63 aa d8 58 ca ad c0 d4 d7 45 c7 03 15 0d 2e 66 85 ce 90 57 e3 e1 83 f7 12 05 24 39 28 6b 59 1e b5 6b 6a 11 32 59 a0 b7 af 96 a7 bf a2 36 e5 10 fe 52 22 54 a1 2f 86 6d cb 1d }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}