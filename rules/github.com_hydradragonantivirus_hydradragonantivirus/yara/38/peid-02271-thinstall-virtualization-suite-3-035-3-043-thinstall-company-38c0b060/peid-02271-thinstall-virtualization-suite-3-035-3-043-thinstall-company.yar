rule PEiD_02271_Thinstall_Virtualization_Suite_3_035_3_043____Thinstall_Company_ {
  meta:
    description = "[Thinstall Virtualization Suite 3.035-3.043 -> Thinstall Company]"
    ep_only     = "true"

  strings:
    $a = { 9C 60 68 53 74 41 6C 68 54 68 49 6E E8 00 00 00 00 58 BB 37 1F 00 00 2B C3 50 68 ?? ?? ?? ?? 68 00 28 00 00 68 04 01 00 00 E8 BA FE FF FF E9 90 FF FF FF CC CC CC CC CC CC CC 55 8B EC 83 C4 F4 FC 53 57 56 8B 75 08 8B 7D 0C C7 45 FC 08 00 00 00 33 DB BA 00 }

  condition:
    $a
}