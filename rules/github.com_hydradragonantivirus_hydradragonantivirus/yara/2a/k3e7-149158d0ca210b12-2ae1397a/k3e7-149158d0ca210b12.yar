rule k3e7_149158d0ca210b12 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e7.149158d0ca210b12"
    cluster      = "k3e7.149158d0ca210b12"
    cluster_size = "3"
    filetype     = ""
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171122"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "virtob scar shyape"
    md5_hashes   = "['bd683c02391481c7d4c822101e15181d','bd683c02391481c7d4c822101e15181d','bd683c02391481c7d4c822101e15181d']"

  strings:
    $hex_string = { af 3d 21 19 ab ad 15 6b dd d0 c0 9e 2c 42 8d 9b f6 cb d1 67 c5 bf 30 b0 68 3c 7b c9 08 5a be bc aa 45 e0 ff 1c 00 92 40 41 5d 9f 74 1a 2b 57 3a d7 a6 36 a0 56 e2 d5 a7 c2 c1 8b 70 fd 89 c8 7c }

  condition:
    filesize > 262144 and filesize < 1048576
    and $hex_string
}