rule k3e9_061cae1dd29b9912 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e9.061cae1dd29b9912"
    cluster      = "k3e9.061cae1dd29b9912"
    cluster_size = "3"
    filetype     = "PE32 executable (GUI) Intel 80386"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171124"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "backdoor peed qukart"
    md5_hashes   = "['5daf7e3a383b5c200458175947561c2b','68024c4993bad39455a8ff924e87c1a2','a302e47ac9a7a0b0cad645fc358f840a']"

  strings:
    $hex_string = { 7b 02 73 74 72 6e 63 6d 70 00 00 00 97 02 76 73 70 72 69 6e 74 66 00 00 6f 6c 65 33 32 2e 44 4c 4c 00 00 00 00 f0 42 00 00 f0 42 00 00 f0 42 00 00 f0 42 00 4f 4c 45 41 55 54 33 32 2e 44 4c 4c }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}