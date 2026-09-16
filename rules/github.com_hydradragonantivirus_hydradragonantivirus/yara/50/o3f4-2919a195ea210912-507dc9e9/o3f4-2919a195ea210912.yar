rule o3f4_2919a195ea210912 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=o3f4.2919a195ea210912"
    cluster      = "o3f4.2919a195ea210912"
    cluster_size = "1760"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "androm backdoor advml"
    md5_hashes   = "['002fda97b8548ea796badd3b9fa63c86','003a419697e25a7874f5a613c1bb9830','04005e035061cfde8165f4b86e07944b']"

  strings:
    $hex_string = "5zWVhOek1qa0FaM0p2ZFhCT1lXMWxBRHhCWkdSRGIyNTBZV04wUjNKdmRYQStZbD"

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}