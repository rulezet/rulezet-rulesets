rule PEiD_01365_Nullsoft_PIMP_Install_System_v1_x_ {
  meta:
    description = "[Nullsoft PIMP Install System v1.x]"
    ep_only     = "true"

  strings:
    $a = { 83 EC 5C 53 55 56 57 FF 15 ?? ?? ?? 00 }

  condition:
    $a
}