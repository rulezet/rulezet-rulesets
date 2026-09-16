rule PEiD_03417_Vx__Spanz_ {
  meta:
    description = "[Vx: Spanz]"
    ep_only     = "true"

  strings:
    $a = { E8 00 00 5E 81 EE ?? ?? 8D 94 ?? ?? B4 1A CD 21 C7 84 }

  condition:
    $a
}