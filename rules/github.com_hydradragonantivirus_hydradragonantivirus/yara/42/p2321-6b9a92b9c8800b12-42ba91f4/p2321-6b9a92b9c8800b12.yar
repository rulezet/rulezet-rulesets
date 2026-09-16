rule p2321_6b9a92b9c8800b12 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=p2321.6b9a92b9c8800b12"
    cluster      = "p2321.6b9a92b9c8800b12"
    cluster_size = "10"
    filetype     = "application/gzip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "fileinfector delf gate"
    md5_hashes   = "['2c53853c02143a19fb2c0e8fb59ba471','320038d5287938dc5d1d5ccecf46d30b','b819de570f95704c3f34f2274facd011']"

  strings:
    $hex_string = { 0c 5a a0 cb fa 03 21 75 a7 77 f8 c5 f4 67 66 f7 48 86 5c c9 3d e6 08 93 cd f6 4c de 0e 33 a3 32 38 31 9b 53 90 a9 dc ed a1 a5 2e 02 6a fb 1b d6 91 2f 18 d9 ec cc c1 54 82 07 f3 b6 8e fd ac 10 }

  condition:
    filesize > 4194304 and filesize < 16777216
    and $hex_string
}