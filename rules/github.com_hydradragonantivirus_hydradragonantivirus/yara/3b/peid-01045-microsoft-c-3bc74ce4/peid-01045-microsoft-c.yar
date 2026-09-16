rule PEiD_01045_Microsoft_C_ {
  meta:
    description = "[Microsoft C]"
    ep_only     = "true"

  strings:
    $a = { B4 30 CD 21 3C 02 73 ?? B8 }

  condition:
    $a
}