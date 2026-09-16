rule k3e9_6a92d79cc2210912 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e9.6a92d79cc2210912"
    cluster      = "k3e9.6a92d79cc2210912"
    cluster_size = "5875"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171122"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "bundler jatif addrop"
    md5_hashes   = "['0002e2597a1bdbf3ba700af17f4358c4','00067ef2d4288932e5376eccc5cbfecb','00e90d4d37d6f4a42fdee0a81042d036']"

  strings:
    $hex_string = { 81 c1 41 56 d4 cc 9f 97 b5 84 47 75 77 8b 2d 3b 9b ad 21 0f 7c 60 3d 09 4e 89 e6 92 6f a3 5e 68 44 18 68 0c 76 e2 74 ac 35 55 3c eb f5 71 11 34 e1 da c8 23 1c 50 55 8c 14 01 16 24 86 88 e5 90 }

  condition:
    filesize > 4194304 and filesize < 16777216
    and $hex_string
}