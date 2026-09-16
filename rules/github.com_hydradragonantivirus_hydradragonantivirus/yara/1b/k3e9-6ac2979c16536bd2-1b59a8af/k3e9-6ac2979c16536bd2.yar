rule k3e9_6ac2979c16536bd2 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e9.6ac2979c16536bd2"
    cluster      = "k3e9.6ac2979c16536bd2"
    cluster_size = "36"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171118"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "adload nsis malicious"
    md5_hashes   = "['001a466b144741d525cf7761cd8e5bcc','0e2d9f2439e06b94ed2174c6ec26432c','54d12d9b4e2b66c69bf416abc8d13f5c']"

  strings:
    $hex_string = { aa 39 af 39 b5 39 3c 3a b3 3a c2 3a d8 3a ed 3a f9 3a 43 3b c3 3c 2a 3e 76 3e 80 3e 9a 3e 7c 3f 00 00 00 20 00 00 ac 00 00 00 37 30 3e 30 b7 30 2e 31 75 32 dc 32 ed 32 fd 32 1b 33 22 33 44 33 }

  condition:
    filesize > 16777216 and filesize < 67108864
    and $hex_string
}