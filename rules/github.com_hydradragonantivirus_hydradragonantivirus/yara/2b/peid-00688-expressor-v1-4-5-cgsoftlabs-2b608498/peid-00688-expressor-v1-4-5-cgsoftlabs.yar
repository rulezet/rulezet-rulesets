rule PEiD_00688_eXpressor_v1_4_5____CGSoftLabs_ {
  meta:
    description = "[eXpressor v1.4.5 -> CGSoftLabs]"
    ep_only     = "true"

  strings:
    $a = { 55 8B EC 83 EC 58 53 56 57 83 65 DC 00 F3 EB 0C }

  condition:
    $a
}