rule k3e9_6a129388cad10b12 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e9.6a129388cad10b12"
    cluster      = "k3e9.6a129388cad10b12"
    cluster_size = "85"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "bundler yantai nsismod"
    md5_hashes   = "['125678a807f6997fc8f7f24167b777ca','1506058c8307d8424a0cc11a020b3eb5','3cbf5874aa2f77862835b47792dc9183']"

  strings:
    $hex_string = { e9 a1 fe ff ff 5f 5e 5d 5b 59 c3 8b 4c 24 04 8b 81 14 08 00 00 85 c0 7c 2b 56 8d 70 41 c1 e6 05 57 03 f1 8d 78 01 8b 06 85 c0 74 10 83 7e fc ff 75 0a 50 ff 15 0c 91 40 00 83 26 00 83 ee 20 4f }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}