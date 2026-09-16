import "pe"
rule AntiVirus_Vaccine_v_1_03 {
  strings:
    $a0 = { FA 33 DB B9 ?? ?? 0E 1F 33 F6 FC AD 35 ?? ?? 03 D8 E2 }

  condition:
    $a0 at pe.entry_point
}