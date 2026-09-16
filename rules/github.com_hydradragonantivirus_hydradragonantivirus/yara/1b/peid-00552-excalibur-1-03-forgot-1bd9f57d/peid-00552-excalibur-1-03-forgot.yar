rule PEiD_00552_Excalibur_1_03____forgot_ {
  meta:
    description = "[Excalibur 1.03 -> forgot]"
    ep_only     = "true"

  strings:
    $a = { E9 00 00 00 00 60 E8 14 00 00 00 5D 81 ED 00 00 00 00 }

  condition:
    $a
}