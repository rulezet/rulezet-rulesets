rule i2321_059e9a55dbeb0932 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=i2321.059e9a55dbeb0932"
    cluster      = "i2321.059e9a55dbeb0932"
    cluster_size = "5"
    filetype     = "PE32 executable (console) Intel 80386"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "backdoor cosmicduke razy"
    md5_hashes   = "['45107076a6e950fcf41c6673906ab41a','5c0d562a64687ecf47d39171772eb83d','eb1d0b109aa483302e2c92403a86f9a4']"

  strings:
    $hex_string = { 25 5b 4e d6 ac 78 24 7b d4 27 57 b6 ff 42 48 f6 68 0f d5 6a ad 63 f5 4f c9 23 d9 ee af cc 9e b5 43 d7 67 9f 8a f8 56 d8 1e 17 b3 0d 31 db ea ec ea 53 69 eb 8e d9 6f c7 06 3e 54 3d 97 df 8d 4d }

  condition:
    filesize > 1024 and filesize < 4096
    and $hex_string
}