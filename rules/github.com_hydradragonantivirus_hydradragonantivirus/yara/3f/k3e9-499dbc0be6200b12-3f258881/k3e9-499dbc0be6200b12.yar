rule k3e9_499dbc0be6200b12 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e9.499dbc0be6200b12"
    cluster      = "k3e9.499dbc0be6200b12"
    cluster_size = "201"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171109"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "lolbot backdoor zusy"
    md5_hashes   = "['00de381f5db9b236cb87a08a662bcb00','0209e3576ecbf2f933487c0732566af2','2ed9b837ce5ecf8260186f2679b929a0']"

  strings:
    $hex_string = { 4c 4e 30 36 35 33 30 00 5c 52 4c 4e 30 36 35 32 37 00 5c 52 4c 54 36 39 39 30 00 5c 52 4c 54 36 39 38 39 00 5c 52 4c 54 36 39 38 38 00 5c 52 4c 54 36 39 38 37 00 44 74 6c 67 65 61 41 65 6c 56 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}