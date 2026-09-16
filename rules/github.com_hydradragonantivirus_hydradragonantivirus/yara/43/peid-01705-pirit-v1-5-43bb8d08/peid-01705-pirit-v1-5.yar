rule PEiD_01705_PIRIT_v1_5_ {
  meta:
    description = "[PIRIT v1.5]"
    ep_only     = "true"

  strings:
    $a = { B4 4D CD 21 E8 ?? ?? FD E8 ?? ?? B4 51 CD 21 }

  condition:
    $a
}