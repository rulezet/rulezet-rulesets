rule n3fd_0842892c5ba31114 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=n3fd.0842892c5ba31114"
    cluster      = "n3fd.0842892c5ba31114"
    cluster_size = "141"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171123"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "browsefox yontoo backdoor"
    md5_hashes   = "['02731b186ee14063c20693d598e3796a','07713ba7e8ae10203c742dba54ef4a19','1fb4f46df1a79cfae148c326ecf1ddb9']"

  strings:
    $hex_string = { 6c 69 6e 67 00 67 65 74 5f 43 6f 6e 76 65 72 74 65 72 73 00 44 65 73 65 72 69 61 6c 69 7a 65 00 63 35 31 36 61 32 30 31 61 61 66 61 64 35 31 38 33 31 64 37 37 63 63 61 34 36 34 32 64 39 62 32 }

  condition:
    filesize > 262144 and filesize < 1048576
    and $hex_string
}