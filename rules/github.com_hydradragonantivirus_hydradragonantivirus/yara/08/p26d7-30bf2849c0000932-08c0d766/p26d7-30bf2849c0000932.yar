rule p26d7_30bf2849c0000932 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=p26d7.30bf2849c0000932"
    cluster         = "p26d7.30bf2849c0000932"
    cluster_size    = "4"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180909"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "symmi malicious heuristic"
    md5_hashes      = "['ed16db585b91630fd284053ec20cee63bf36f53d','ac2028f09eb9139475a5ca501d52ab0aa005a27d','2880d47f2dc9ab962e7771421f89298a1b96d198']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=p26d7.30bf2849c0000932"

  strings:
    $hex_string = { c0 f2 ae f7 d1 49 83 cd ff 8b f9 33 d2 85 ff 7e 27 8a 44 24 18 8a 1c 32 8a cb 80 e1 80 80 f9 80 75 0b 8a 4c 32 01 42 84 c9 74 0d eb 06 3a d8 75 02 8b ea 42 3b d7 7c dd 5f 8b c5 5e 5d 5b c3 90 }

  condition:
    filesize > 4194304 and filesize < 16777216
    and $hex_string
}