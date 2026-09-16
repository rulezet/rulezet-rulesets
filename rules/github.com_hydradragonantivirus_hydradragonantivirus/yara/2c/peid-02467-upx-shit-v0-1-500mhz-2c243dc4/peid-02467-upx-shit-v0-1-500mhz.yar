rule PEiD_02467_UPX_Shit_v0_1____500mhz_ {
  meta:
    description = "[UPX-Shit v0.1 -> 500mhz]"
    ep_only     = "true"

  strings:
    $a = { E8 ?? ?? ?? ?? 5E 83 C6 ?? AD 89 C7 AD 89 C1 AD 30 07 47 E2 ?? AD FF E0 C3 }

  condition:
    $a
}