rule PEiD_00217_ASPack_v1_08_01_ {
  meta:
    description = "[ASPack v1.08.01]"
    ep_only     = "true"

  strings:
    $a = { 60 EB 0A 5D EB 02 FF 25 45 FF E5 E8 E9 E8 F1 FF FF FF E9 81 ?? ?? ?? 44 ?? BB 10 ?? 44 ?? 03 DD 2B 9D }

  condition:
    $a
}