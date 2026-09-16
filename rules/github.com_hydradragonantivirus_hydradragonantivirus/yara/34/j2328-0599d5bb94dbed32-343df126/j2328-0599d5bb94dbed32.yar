rule j2328_0599d5bb94dbed32 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=j2328.0599d5bb94dbed32"
    cluster         = "j2328.0599d5bb94dbed32"
    cluster_size    = "41"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "script exploit html"
    md5_hashes      = "['36ee0a83c78af02e7f733aba67e27e9db428bbb5','560a7906e3779c0aa58d637ecaa127ffb23d0b97','6903f1fa750030955335d40a060d4bf95459b14e']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=j2328.0599d5bb94dbed32"

  strings:
    $hex_string = { 64 65 73 63 72 69 70 74 69 6f 6e 3e 3c 21 5b 43 44 41 54 41 5b 32 30 31 38 2d 30 33 2d 32 39 20 20 e5 b9 bc e7 a8 9a e5 9c 92 e8 88 89 e8 be a6 e6 ad 8c e5 94 b1 e6 af 94 e8 b3 bd ef bc 8c e9 }

  condition:
    filesize > 4096 and filesize < 16384
    and $hex_string
}