rule PEiD_03409_Vx__November_17_768_ {
  meta:
    description = "[Vx: November 17.768]"
    ep_only     = "true"

  strings:
    $a = { E8 ?? ?? 5E 81 EE ?? ?? 50 33 C0 8E D8 80 3E ?? ?? ?? 0E 1F ?? ?? FC }

  condition:
    $a
}