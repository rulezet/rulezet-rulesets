rule j3f8_7094d6c3c8000130 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=j3f8.7094d6c3c8000130"
    cluster      = "j3f8.7094d6c3c8000130"
    cluster_size = "14"
    filetype     = "application/octet-stream"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171124"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "shedun androidos fyec"
    md5_hashes   = "['2af3dfe4e52177e825188a861f5904c1','32b30ea99441f740c6a163598823958c','fe669cb1cc19fa22f367d428cfc92fed']"

  strings:
    $hex_string = { 61 62 6c 65 00 01 62 00 09 63 6c 61 73 73 4e 61 6d 65 00 05 63 6c 6f 73 65 00 15 63 75 72 72 65 6e 74 41 63 74 69 76 69 74 79 54 68 72 65 61 64 00 06 65 78 69 73 74 73 00 07 66 6f 72 4e 61 6d }

  condition:
    filesize > 4096 and filesize < 16384
    and $hex_string
}