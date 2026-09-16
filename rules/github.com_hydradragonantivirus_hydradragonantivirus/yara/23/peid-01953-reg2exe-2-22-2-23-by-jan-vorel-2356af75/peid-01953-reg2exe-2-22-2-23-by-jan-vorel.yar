rule PEiD_01953_Reg2Exe_2_22_2_23___by_Jan_Vorel_ {
  meta:
    description = "[Reg2Exe 2.22/2.23 - by Jan Vorel]"
    ep_only     = "true"

  strings:
    $a = { 6A 00 E8 2F 1E 00 00 A3 C4 35 40 00 E8 2B 1E 00 00 6A 0A 50 6A 00 FF 35 C4 35 40 00 E8 07 00 00 00 50 E8 1B 1E 00 00 CC 68 48 00 00 00 68 00 00 00 00 68 C8 35 40 00 E8 76 16 00 00 83 C4 0C 8B 44 24 04 A3 CC 35 40 00 68 00 00 00 00 68 A0 0F 00 00 68 00 00 }

  condition:
    $a
}