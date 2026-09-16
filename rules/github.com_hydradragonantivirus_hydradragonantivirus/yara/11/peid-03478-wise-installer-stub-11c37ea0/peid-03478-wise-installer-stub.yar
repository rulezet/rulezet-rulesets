rule PEiD_03478_Wise_Installer_Stub_ {
  meta:
    description = "[Wise Installer Stub]"
    ep_only     = "false"

  strings:
    $a = { 55 8B EC 81 EC ?? ?? 00 00 53 56 57 6A 01 5E 6A 04 89 75 E8 FF 15 ?? 40 40 00 FF 15 ?? 40 40 00 8B F8 89 7D ?? 8A 07 3C 22 0F 85 ?? 00 00 00 8A 47 01 47 89 7D ?? 33 DB 3A C3 74 0D 3C 22 74 09 8A 47 01 47 89 7D ?? EB EF 80 3F 22 75 04 47 89 7D ?? 80 3F 20 75 09 47 80 3F 20 74 FA 89 7D ?? 53 FF 15 ?? 40 40 00 80 3F 2F 89 45 ?? 75 ?? 8A 47 01 3C 53 74 04 3C 73 75 06 89 35 }

  condition:
    $a
}