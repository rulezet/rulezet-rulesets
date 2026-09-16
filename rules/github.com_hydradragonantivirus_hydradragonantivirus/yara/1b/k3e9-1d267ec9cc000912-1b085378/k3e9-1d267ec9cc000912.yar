rule k3e9_1d267ec9cc000912 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e9.1d267ec9cc000912"
    cluster      = "k3e9.1d267ec9cc000912"
    cluster_size = "298238"
    filetype     = "PE32 executable (GUI) Intel 80386"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171122"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "small generickd malicious"
    md5_hashes   = "['000059b42a61ba3849c6529edead9988','0000a9542946c9d2d6a490659b226469','000b132c8db967a9687138f7099c2760']"

  strings:
    $hex_string = { b7 5b cf 1c 51 43 56 87 0f 75 ca 79 f6 89 54 a0 6a 1f 49 4b de d1 f7 50 0c 99 ef 95 3f d3 22 5e 9c 0a 28 d6 7b 34 96 7d 39 1a 3b 64 08 03 92 5d b4 e1 ed a1 66 97 fa 7c c7 24 b8 ff 25 b1 13 d8 }

  condition:
    filesize > 262144 and filesize < 1048576
    and $hex_string
}