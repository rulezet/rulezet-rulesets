rule PEiD_03398_Vx__Involuntary_1349_ {
  meta:
    description = "[Vx: Involuntary.1349]"
    ep_only     = "true"

  strings:
    $a = { ?? BA ?? ?? B9 ?? ?? 8C DD ?? 8C C8 ?? 8E D8 8E C0 33 F6 8B FE FC ?? ?? AD ?? 33 C2 AB }

  condition:
    $a
}