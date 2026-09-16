import "pe"
rule Vx__Ncu_Li_1688 {
  strings:
    $a0 = { 0E 1E B8 55 AA CD 21 3D 49 4C 74 ?? 0E 0E 1F 07 E8 }

  condition:
    $a0 at pe.entry_point
}