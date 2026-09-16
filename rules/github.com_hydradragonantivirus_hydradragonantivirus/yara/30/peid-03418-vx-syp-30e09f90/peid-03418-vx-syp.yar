rule PEiD_03418_Vx__SYP_ {
  meta:
    description = "[Vx: SYP]"
    ep_only     = "true"

  strings:
    $a = { 47 8B C2 05 1E 00 52 8B D0 B8 02 3D CD 21 8B D8 5A }

  condition:
    $a
}