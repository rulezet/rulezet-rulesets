rule k3e9_6b64d34a9b2b5912 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e9.6b64d34a9b2b5912"
    cluster      = "k3e9.6b64d34a9b2b5912"
    cluster_size = "3"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171123"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "virut virtob patched"
    md5_hashes   = "['19a8c81a9ff17d8ecff5c82acb69660c','3f604895004c719000faea8c72380177','ae32c11f74d389f0afc6f49ab782d03b']"

  strings:
    $hex_string = { c7 89 89 ff b8 92 89 ff 57 3d 34 fd 9d 81 7e fe b5 97 96 ff ba 99 99 ff b3 91 90 fe 98 71 6e fb 78 51 4c f5 52 32 29 e7 3f 22 17 cf 45 28 1d a8 4b 2b 22 5e 4e 2f 24 27 55 33 22 0c bf 9e 9b d8 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}