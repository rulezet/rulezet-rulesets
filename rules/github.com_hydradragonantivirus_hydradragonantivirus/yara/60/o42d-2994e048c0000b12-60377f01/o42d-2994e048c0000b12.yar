rule o42d_2994e048c0000b12 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=o42d.2994e048c0000b12"
    cluster      = "o42d.2994e048c0000b12"
    cluster_size = "7"
    filetype     = ""
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171123"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "installmiez extinstall installcore"
    md5_hashes   = "['031955448b315131960b16e0c274d9f7','0edb0df061727e8662f739b956252fd6','da7c2a139db1a4ce36f0b4196bccff64']"

  strings:
    $hex_string = { be e3 f8 13 66 e4 de 42 25 b9 8d a9 5f 04 e2 d5 91 16 85 1e ad 76 61 7f b4 cc f5 0a 9d ae 78 2e cf 64 56 6e bb fd 79 e6 7d 59 af 1c f6 ec 3b 32 3a 5d 4c 69 88 80 d1 c1 58 99 27 eb 1b 55 ab fe }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}