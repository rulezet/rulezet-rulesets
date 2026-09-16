rule j2321_131257d2c92a7b36 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=j2321.131257d2c92a7b36"
    cluster      = "j2321.131257d2c92a7b36"
    cluster_size = "3"
    filetype     = "application/gzip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171124"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "upatre bublik generickd"
    md5_hashes   = "['61cae9d8f337cef85ca5ca46d690de4a','69ace514d0fde098f8573e848660c4e8','e6a76657e10cbd2107a8b4ca41cd3706']"

  strings:
    $hex_string = { 38 8a 91 34 12 31 58 ef b6 f3 9d a8 fd 18 e5 47 28 3f 48 f9 3e ca b7 20 ef 0c de 66 19 7b 11 65 e2 c8 17 81 df 72 ed fa 1a 6b 51 0f 68 3c 47 63 bb 14 9c cd 23 bd bc 45 6d 05 7c 75 dc 5c 5b d5 }

  condition:
    filesize > 4096 and filesize < 16384
    and $hex_string
}