rule n3f7_7adb10b9c9000912 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=n3f7.7adb10b9c9000912"
    cluster      = "n3f7.7adb10b9c9000912"
    cluster_size = "5"
    filetype     = "text/html"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171123"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "ramnit html script"
    md5_hashes   = "['22f866c8fad24c5488a133e125b6d760','29b501a37fffeac0750b4e56f203fd86','d8571d83298a802e9ece82261087d65b']"

  strings:
    $hex_string = "462B66C70A899BEDDEA42DF40592D70CA17E62B0FC50D7F5405B5131C2838336"

  condition:
    filesize > 262144 and filesize < 1048576
    and $hex_string
}