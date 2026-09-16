rule PEiD_00685_eXPressor_V1_3____CGSoftLabs_ {
  meta:
    description = "[eXPressor V1.3 -> CGSoftLabs]"
    ep_only     = "true"

  strings:
    $a = { 55 8B EC 83 EC ?? 53 56 57 EB 0C 45 }

  condition:
    $a
}