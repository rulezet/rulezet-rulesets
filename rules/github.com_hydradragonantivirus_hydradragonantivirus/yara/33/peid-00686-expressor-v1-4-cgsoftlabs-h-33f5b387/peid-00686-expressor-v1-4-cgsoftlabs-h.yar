rule PEiD_00686_eXPressor_v1_4____CGSoftLabs__h__ {
  meta:
    description = "[eXPressor v1.4 -> CGSoftLabs (h)]"
    ep_only     = "true"

  strings:
    $a = { 55 8B EC 83 EC ?? 53 56 57 EB 0C 45 78 50 72 2D 76 2E 31 2E 34 2E 2E B8 }

  condition:
    $a
}