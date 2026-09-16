rule PEiD_00915_Inno_Installer_v5_1_2_ {
  meta:
    description = "[Inno Installer v5.1.2]"
    ep_only     = "false"

  strings:
    $a = { 9C 60 E8 00 00 00 00 58 BB DC 1E 00 00 2B C3 50 68 ?? ?? ?? ?? 68 00 50 00 00 68 D8 00 00 00 E8 C1 FE FF FF E9 97 FF FF FF CC CC }

  condition:
    $a
}