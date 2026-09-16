rule j3e9_55b8380140000932 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=j3e9.55b8380140000932"
    cluster      = "j3e9.55b8380140000932"
    cluster_size = "457"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171109"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "hematite hworld infector"
    md5_hashes   = "['0072ce5e80f367a2f04364fe2a9ac96a','00dd9a1ff4d004b193792dd8c495734f','0ad66274a92d3af74e0ada43719174d0']"

  strings:
    $hex_string = { 05 01 05 e8 00 00 00 00 01 01 01 ac 01 01 01 50 01 01 01 56 01 01 01 57 01 01 01 51 23 04 05 b9 1d f3 01 00 08 33 c9 81 c1 1d f3 01 00 0b b9 d3 f2 00 00 81 c1 4a 00 01 00 0b b9 02 fa 06 00 81 }

  condition:
    filesize > 4096 and filesize < 16384
    and $hex_string
}