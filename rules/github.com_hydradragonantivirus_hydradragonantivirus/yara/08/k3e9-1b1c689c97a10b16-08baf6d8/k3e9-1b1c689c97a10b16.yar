rule k3e9_1b1c689c97a10b16 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e9.1b1c689c97a10b16"
    cluster      = "k3e9.1b1c689c97a10b16"
    cluster_size = "477"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "neshta nestha hllp"
    md5_hashes   = "['00a37a727c2021fb2382088b079143ba','01ebdfa6028ce6eb13faf7b5fe1f901c','0cb533c0db7ab31639e91af7d2149c3c']"

  strings:
    $hex_string = { 74 06 50 e8 af db ff ff 83 c4 2c 5e 5b c3 90 53 ba 94 91 40 00 0f b6 0a e3 0a 42 31 db 43 d3 e3 39 c3 7c f1 91 5b c3 55 8b ec 33 c0 8b 55 08 8a 52 f2 80 fa 02 73 09 8b 4d 08 80 79 f3 01 75 16 }

  condition:
    filesize > 262144 and filesize < 1048576
    and $hex_string
}