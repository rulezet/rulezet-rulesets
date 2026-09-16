rule o3e9_1651a8629ed36b1a {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=o3e9.1651a8629ed36b1a"
    cluster      = "o3e9.1651a8629ed36b1a"
    cluster_size = "523"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171109"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "installmonster installmonstr malicious"
    md5_hashes   = "['00a68564fc3118c09bbf6c8d9454dfc1','02054e750be6e13ab3aba3103c32a02a','09a7608afe13467c670b3b1cfa121b3f']"

  strings:
    $hex_string = { ba 28 1d d9 12 4f a5 72 3a 4c 10 80 7c 2c 75 b8 0f 2d c0 bf e5 2f 2b d1 c0 29 a0 e2 8f a1 8f d1 00 16 96 62 dd b8 d8 c3 d9 87 9e 65 01 d2 bd 7a 3e f2 34 8f dd ea e1 f6 ef 8d 81 ac b2 cb ac ff }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}