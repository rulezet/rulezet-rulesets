rule PEiD_01623_PENightMare_v1_3_ {
  meta:
    description = "[PENightMare v1.3]"
    ep_only     = "true"

  strings:
    $a = { 60 E8 00 00 00 00 5D B9 ?? ?? ?? ?? 80 31 15 41 81 F9 }

  condition:
    $a
}