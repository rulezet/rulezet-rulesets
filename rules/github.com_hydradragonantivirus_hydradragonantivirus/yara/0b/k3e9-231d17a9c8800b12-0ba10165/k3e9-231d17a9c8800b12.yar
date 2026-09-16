rule k3e9_231d17a9c8800b12 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e9.231d17a9c8800b12"
    cluster      = "k3e9.231d17a9c8800b12"
    cluster_size = "4116"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171109"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "mydoom email malicious"
    md5_hashes   = "['0029f92fdb9181a7ab8224fc2ba3fd4d','002f4fe003bfaf888026402fd4cdd541','011cf9c881fcf19d9db85d3ed9adf911']"

  strings:
    $hex_string = { 05 06 2f a1 ed 36 82 dc a9 2e 07 de 2b 58 5d 4e b6 e7 b3 e0 01 e2 01 ec 6b e4 d8 88 d1 9b 15 92 a8 04 21 88 3c 67 74 3f 2a c6 5e a7 2c 38 c5 3a 33 4d 01 40 af 9a 65 88 50 bc 47 45 89 4b c5 12 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}