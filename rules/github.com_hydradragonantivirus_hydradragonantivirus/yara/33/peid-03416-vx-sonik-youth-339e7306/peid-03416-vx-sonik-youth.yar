rule PEiD_03416_Vx__Sonik_Youth_ {
  meta:
    description = "[Vx: Sonik Youth]"
    ep_only     = "true"

  strings:
    $a = { 8A 16 02 00 8A 07 32 C2 88 07 43 FE C2 81 FB }

  condition:
    $a
}