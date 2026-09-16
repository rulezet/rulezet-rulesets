rule PEiD_02342_Unnamed_Scrambler_2_5_1_Beta_2____2_5_2____p0ke_ {
  meta:
    description = "[Unnamed Scrambler 2.5.1(Beta 2) / 2.5.2 -> p0ke]"
    ep_only     = "true"

  strings:
    $a = { 55 8B EC B9 ?? 00 00 00 6A 00 6A 00 49 75 F9 53 56 57 B8 ?? ?? 40 00 E8 ?? EA FF FF 33 C0 55 68 ?? ?? 40 00 64 FF 30 64 89 20 BA ?? ?? 40 00 B8 ?? ?? 40 00 E8 63 F3 FF FF 8B D8 85 DB 75 07 6A 00 E8 ?? ?? FF FF BA ?? ?? 40 00 8B C3 8B 0D ?? ?? 40 00 E8 }

  condition:
    $a
}