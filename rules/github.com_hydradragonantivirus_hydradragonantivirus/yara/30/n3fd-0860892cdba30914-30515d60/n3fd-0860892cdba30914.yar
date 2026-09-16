rule n3fd_0860892cdba30914 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=n3fd.0860892cdba30914"
    cluster      = "n3fd.0860892cdba30914"
    cluster_size = "87"
    filetype     = ""
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171123"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "browsefox hacekomoe yontoo"
    md5_hashes   = "['01d9ce547b88479b6e879aefae9b78cc','0286601b3aec9053f51e4ca691161937','2fd6d789fec974fa917d8124c58bb82a']"

  strings:
    $hex_string = { 53 74 61 72 74 00 61 72 67 73 00 4f 6e 53 74 6f 70 00 63 38 65 31 64 36 38 34 35 32 64 31 33 32 36 63 33 30 65 61 37 36 39 62 30 36 64 63 30 66 38 33 37 00 4f 6e 43 75 73 74 6f 6d 43 6f 6d 6d }

  condition:
    filesize > 262144 and filesize < 1048576
    and $hex_string
}