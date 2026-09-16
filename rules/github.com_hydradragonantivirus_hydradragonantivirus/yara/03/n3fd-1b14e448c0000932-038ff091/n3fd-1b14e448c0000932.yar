rule n3fd_1b14e448c0000932 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=n3fd.1b14e448c0000932"
    cluster      = "n3fd.1b14e448c0000932"
    cluster_size = "19"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171109"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "zusy malicious attribute"
    md5_hashes   = "['0bf08407ab6e90d066026d0c3635f72f','14647512ff29cf7406e730d4bc321da4','a7320f32d940b8bb718c0c3a6c2d6362']"

  strings:
    $hex_string = { 51 75 31 fb 65 70 11 fe 29 f8 10 ff d2 7f fd ab 7e 15 f2 16 cc a9 bf f2 b7 c3 c4 ff ab 8f 7f b7 ff 7a b9 63 93 78 6f 89 05 9e de f9 97 ee 1f 64 bf ef af 4f 7d 59 fe fa af ff 0b a8 90 3f f8 1f }

  condition:
    filesize > 262144 and filesize < 1048576
    and $hex_string
}