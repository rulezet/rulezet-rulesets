rule k3e9_092b311e6a231912 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e9.092b311e6a231912"
    cluster      = "k3e9.092b311e6a231912"
    cluster_size = "94"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171118"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "jeefo hidrag adload"
    md5_hashes   = "['0692cb183a85a7b1c5409ec00a937566','0a6617823878a9bf0710106969957f8c','31dae04adc1fab39550b4a07dc9cdf03']"

  strings:
    $hex_string = { bf 29 c1 30 c3 2b c5 0c c7 31 c9 36 cb 31 cd 17 cf 3e d1 38 d3 43 d5 d6 d7 7c db da db dc dd 0e df 14 e1 12 e3 1d e5 16 e7 1c e9 2c eb 1c ed ee ef 3c f1 08 f3 f5 f5 39 f7 67 f9 67 fb 6c fd 5f }

  condition:
    filesize > 262144 and filesize < 1048576
    and $hex_string
}