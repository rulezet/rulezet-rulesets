rule PEiD_00093_AntiVirus_Vaccine_v_1_03_ {
  meta:
    description = "[AntiVirus Vaccine v.1.03]"
    ep_only     = "true"

  strings:
    $a = { FA 33 DB B9 ?? ?? 0E 1F 33 F6 FC AD 35 ?? ?? 03 D8 E2 }

  condition:
    $a
}