rule n3ef_42549099ea210b14 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=n3ef.42549099ea210b14"
    cluster      = "n3ef.42549099ea210b14"
    cluster_size = "323"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171122"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "browsefox yontoo browse"
    md5_hashes   = "['011114b08b7f0717338b4f909f0ade5a','02067211edc8d2c4964e570e458bbee3','110c0e71b31d868aa01164b8de3d4462']"

  strings:
    $hex_string = { 31 61 38 34 37 65 36 38 39 35 33 31 61 64 39 31 64 61 62 63 61 00 4f 4b 00 49 6e 74 65 72 6e 61 6c 00 50 65 72 6d 00 41 62 6f 72 74 00 42 75 73 79 00 4c 6f 63 6b 65 64 00 4e 6f 4d 65 6d 00 52 }

  condition:
    filesize > 262144 and filesize < 1048576
    and $hex_string
}