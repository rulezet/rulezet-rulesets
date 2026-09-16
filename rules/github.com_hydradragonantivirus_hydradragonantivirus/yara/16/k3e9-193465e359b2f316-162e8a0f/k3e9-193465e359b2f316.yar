rule k3e9_193465e359b2f316 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e9.193465e359b2f316"
    cluster      = "k3e9.193465e359b2f316"
    cluster_size = "88"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "installcore unwanted riskware"
    md5_hashes   = "['06778833d4aa973047d3cb67cb75db63','07bbb98423005df3f2110df2e7009ff9','4c11ce3ee65c2b7d611c95e7eed4045a']"

  strings:
    $hex_string = { 2b c0 5c 60 4f f1 80 40 75 a5 65 f3 18 51 59 c2 86 0d 7d da e5 ba 92 fe 6a a1 57 93 66 b6 61 36 5e e0 e2 c9 28 54 73 04 bb cd a0 05 52 35 af cb 6f 7b b1 0f b3 ac b4 90 d6 02 dd 1d 32 07 ae e7 }

  condition:
    filesize > 262144 and filesize < 1048576
    and $hex_string
}