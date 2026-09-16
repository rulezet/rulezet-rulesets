rule j3e9_030f3844a5e463b6 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=j3e9.030f3844a5e463b6"
    cluster      = "j3e9.030f3844a5e463b6"
    cluster_size = "7"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "fakeav kazy apdg"
    md5_hashes   = "['26fd603f3db7df96c491fd158ad3d045','7e10eb7effbbaaad4c8786d36a8154c0','dca7cc648f5edf5c36cbabe4b3eca379']"

  strings:
    $hex_string = { 36 4b 19 1a eb 56 18 b9 9c 74 cb 73 a6 71 21 3e 85 87 5d da 35 aa 61 1b af 07 fc 29 7c 9e 80 17 8f 9a cc e6 42 37 22 67 b7 bc e2 76 de d9 68 cf 8a fe 23 4c b8 fd 43 53 88 8e 2b 44 5c 57 1d ac }

  condition:
    filesize > 262144 and filesize < 1048576
    and $hex_string
}