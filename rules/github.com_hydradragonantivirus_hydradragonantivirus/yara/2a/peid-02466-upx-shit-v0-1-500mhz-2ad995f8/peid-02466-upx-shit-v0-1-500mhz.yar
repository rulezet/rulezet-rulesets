rule PEiD_02466_UPX_Shit_v0_1____500mhz_ {
  meta:
    description = "[UPX-Shit v0.1 -> 500mhz]"
    ep_only     = "true"

  strings:
    $a = { E8 00 00 00 00 5E 83 C6 14 AD 89 C7 AD 89 C1 AD 30 07 47 E2 FB AD FF E0 C3 00 ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? 00 55 50 58 2D 53 68 69 74 20 76 30 2E 31 20 2D 20 77 77 77 2E 62 6C 61 63 6B 6C 6F 67 69 63 2E 6E 65 74 20 2D 20 63 6F 64 65 20 62 79 20 5B 35 30 30 6D 68 7A 5D }

  condition:
    $a
}