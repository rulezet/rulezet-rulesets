rule p3e9_33183b49c8000b12 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=p3e9.33183b49c8000b12"
    cluster      = "p3e9.33183b49c8000b12"
    cluster_size = "10"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171123"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "virlock nabucur cryptor"
    md5_hashes   = "['0e176edd2788660f3626bd6e18c92a46','5a441b33fff3b8882f6c8c4940dec646','d8a1f1a387c5b1901ae9253c102e4bc2']"

  strings:
    $hex_string = { 3e 02 fb fb f9 79 94 a8 f2 ff 08 38 f5 ff 32 5b fe ff 53 76 fe ff 73 8e fe ff 8b a3 f8 ff a4 b4 ec ff b6 bc df ff bc c6 d4 ff af d7 ca ff 8e dc be ff 4a d2 9c ff 0f bc 79 ff 00 a7 6b ff 03 98 }

  condition:
    filesize > 4194304 and filesize < 16777216
    and $hex_string
}