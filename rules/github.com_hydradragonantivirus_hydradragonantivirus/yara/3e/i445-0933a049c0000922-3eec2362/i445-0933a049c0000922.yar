rule i445_0933a049c0000922 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=i445.0933a049c0000922"
    cluster      = "i445.0933a049c0000922"
    cluster_size = "5"
    filetype     = "application/octet-stream"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "vbsworm winlnk jenxcus"
    md5_hashes   = "['030c51e2f4fd37d9b1cd88a10369d265','28965d30d91169430fc7e74bc018ec18','e4e62c0ed11ab31df750ed42f99fa862']"

  strings:
    $hex_string = { 00 26 00 63 00 6c 00 73 00 26 00 73 00 74 00 61 00 72 00 74 00 20 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 22 00 20 00 22 00 45 00 78 00 63 00 65 00 6c 00 2e 00 57 00 73 00 46 }

  condition:
    filesize > 1024 and filesize < 4096
    and $hex_string
}