rule PEiD_01955_Reg2Exe_2_24___by_Jan_Vorel_ {
  meta:
    description = "[Reg2Exe 2.24 - by Jan Vorel]"
    ep_only     = "true"

  strings:
    $a = { 6A 00 E8 CF 20 00 00 A3 F4 45 40 00 E8 CB 20 00 00 6A 0A 50 6A 00 FF 35 F4 45 40 00 E8 07 00 00 00 50 E8 BB 20 00 00 CC 68 48 00 00 00 68 00 00 00 00 68 F8 45 40 00 E8 06 19 00 00 83 C4 0C 8B 44 24 04 A3 FC 45 40 00 68 00 00 00 00 68 A0 0F 00 00 68 00 00 }

  condition:
    $a
}