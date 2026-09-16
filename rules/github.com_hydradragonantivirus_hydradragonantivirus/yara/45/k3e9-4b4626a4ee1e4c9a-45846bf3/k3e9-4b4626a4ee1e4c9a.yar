rule k3e9_4b4626a4ee1e4c9a {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e9.4b4626a4ee1e4c9a"
    cluster      = "k3e9.4b4626a4ee1e4c9a"
    cluster_size = "3"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171123"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "virut virtob malicious"
    md5_hashes   = "['d22d5e187e11684fb0443c06a38a3751','d4ffba1ff4deaa6be6d547340ce5d1ff','e311a0ab73afd64a261e5d04e9152905']"

  strings:
    $hex_string = { 8a 08 40 84 c9 75 f9 2b c2 8b f0 83 fe 04 8b fe 73 04 33 c0 eb 3e 6a 0b 68 7c 32 00 01 53 ff 15 50 12 00 01 83 c4 0c 85 c0 75 05 8d 46 f6 eb 24 85 f6 74 09 80 3c 1f 5c 74 03 4f 75 f7 b8 7c bd }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}