rule ek_submissions {
  meta:
    author      = "@abhinavbom"
    maltype     = "NA"
    version     = "0.1"
    description = "Detects pcaps uploaded to VT and matches IDS detections for Exploit kits"
    date        = "23/06/2015"

  strings:
    $magic = { D4 C3 B2 A1 }
    $tags  = "exploit-kit"

  condition:
    $magic at 0 and $tags
}