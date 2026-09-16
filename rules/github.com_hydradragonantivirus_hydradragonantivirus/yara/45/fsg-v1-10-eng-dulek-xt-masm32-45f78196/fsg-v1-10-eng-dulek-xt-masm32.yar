import "pe"
rule FSG_v1_10__Eng_____dulek_xt_____MASM32_ {
  strings:
    $a0 = { EB 01 DB E8 02 00 00 00 86 43 5E 8D 1D D0 75 CF 83 C1 EE 1D 68 50 ?? 8F 83 EB 02 3D 0F 5A }

  condition:
    $a0 at pe.entry_point
}