rule k3e9_3164bcc1c8000932 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e9.3164bcc1c8000932"
    cluster      = "k3e9.3164bcc1c8000932"
    cluster_size = "100105"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171122"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "generickd bublik zbot"
    md5_hashes   = "['00004c073f61545ddd233b547d90b738','0001882b740701270c1a2a671b25dce7','00116affed68154ee20c0a516dd38f1e']"

  strings:
    $hex_string = { a1 20 15 84 9b 22 c0 f5 99 d1 28 47 c6 12 eb 59 36 40 1c 51 d0 e6 9c d2 af 04 2c 21 0c fb 81 54 8f a7 4c 93 08 82 09 1a f7 91 a2 8d 44 0a 94 4f 0f 89 6a b5 86 c4 e8 11 8c ec 38 4d 50 e4 a0 e3 }

  condition:
    filesize > 262144 and filesize < 1048576
    and $hex_string
}