rule i3ed_04eb2a4928a00332 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=i3ed.04eb2a4928a00332"
    cluster      = "i3ed.04eb2a4928a00332"
    cluster_size = "1507"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "debris gamarue zusy"
    md5_hashes   = "['0019e379ff0268c2c979499dc850e8d1','002ea48674cf132f67a497c6a21920a5','030e19149e4cd0a779fbdd8dfacbd27d']"

  strings:
    $hex_string = { 8d 71 fc 3b f0 72 12 8b 0e 85 c9 74 07 ff d1 a1 40 32 00 10 83 ee 04 eb ea 50 ff 15 18 20 00 10 83 25 40 32 00 10 00 59 5e 6a 01 58 c2 0c 00 55 8b ec 53 8b 5d 08 56 8b 75 0c 57 8b 7d 10 85 f6 }

  condition:
    filesize > 4096 and filesize < 16384
    and $hex_string
}