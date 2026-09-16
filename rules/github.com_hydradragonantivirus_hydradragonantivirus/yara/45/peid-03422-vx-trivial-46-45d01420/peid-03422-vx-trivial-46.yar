rule PEiD_03422_Vx__Trivial_46_ {
  meta:
    description = "[Vx: Trivial.46]"
    ep_only     = "true"

  strings:
    $a = { B4 4E B1 20 BA ?? ?? CD 21 BA ?? ?? B8 ?? 3D CD 21 }

  condition:
    $a
}