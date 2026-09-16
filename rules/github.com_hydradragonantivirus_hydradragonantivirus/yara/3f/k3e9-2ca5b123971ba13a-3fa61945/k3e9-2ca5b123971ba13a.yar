rule k3e9_2ca5b123971ba13a {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e9.2ca5b123971ba13a"
    cluster      = "k3e9.2ca5b123971ba13a"
    cluster_size = "373"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "malicious backdoor laqma"
    md5_hashes   = "['07f7c3701270da6c3ae3d310c686fb3d','0d5671bfea42292244c1aca3fa75b08d','321176032a3a2208647fbf7364b94085']"

  strings:
    $hex_string = { 85 c0 74 77 8b 5d dc 8d 45 b4 50 ff 15 4c b1 40 00 8b 4d b8 a1 64 e6 40 00 8d 79 ff f7 d7 23 fe 2b f9 8b f0 4e f7 de 1b f6 83 e6 f1 83 c6 11 0f af f1 03 f3 3b fe 89 4d f8 72 40 83 f8 01 74 5c }

  condition:
    filesize > 65536 and filesize < 262144
    and $hex_string
}