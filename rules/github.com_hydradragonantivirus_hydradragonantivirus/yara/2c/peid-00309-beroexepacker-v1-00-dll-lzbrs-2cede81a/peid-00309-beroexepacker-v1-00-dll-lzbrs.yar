rule PEiD_00309_BeRoEXEPacker_v1_00_DLL__LZBRS__ {
  meta:
    description = "[BeRoEXEPacker v1.00 DLL [LZBRS]]"
    ep_only     = "true"

  strings:
    $a = { 83 7C 24 08 01 0F 85 ?? ?? ?? ?? 60 BE ?? ?? ?? ?? BF ?? ?? ?? ?? FC AD 8D 1C 07 B0 80 3B FB 73 3B E8 1C 00 00 00 72 03 A4 EB F2 E8 1A 00 00 00 8D 51 FF E8 12 00 00 00 56 8B F7 2B F2 F3 A4 5E EB DB 02 C0 75 03 AC 12 C0 C3 33 }

  condition:
    $a
}