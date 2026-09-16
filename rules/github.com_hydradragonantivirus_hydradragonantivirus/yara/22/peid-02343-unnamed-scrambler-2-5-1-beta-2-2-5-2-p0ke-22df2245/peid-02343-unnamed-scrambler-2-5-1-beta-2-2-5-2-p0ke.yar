rule PEiD_02343_Unnamed_Scrambler_2_5_1_Beta_2____2_5_2____p0ke_ {
  meta:
    description = "[Unnamed Scrambler 2.5.1(Beta 2) / 2.5.2 -> p0ke]"
    ep_only     = "true"

  strings:
    $a = { 55 8B EC B9 ?? 00 00 00 6A 00 6A 00 49 75 F9 53 56 57 B8 ?? ?? 40 00 E8 ?? EA FF FF 33 C0 55 68 ?? ?? 40 00 64 FF 30 64 89 20 BA ?? ?? 40 00 B8 ?? ?? 40 00 E8 63 F3 FF FF 8B D8 85 DB 75 07 6A 00 E8 ?? ?? FF FF BA ?? ?? 40 00 8B C3 8B 0D ?? ?? 40 00 E8 ?? ?? FF FF C7 05 ?? ?? 40 00 0A 00 00 00 BB ?? ?? 40 00 BE ?? ?? 40 00 BF ?? ?? 40 00 B8 ?? ?? 40 00 BA 04 00 00 00 E8 ?? EB FF FF 83 3B 00 74 04 33 C0 89 03 8B D7 8B C6 E8 0A F3 FF FF 89 03 83 3B 00 0F 84 F7 04 00 00 B8 ?? ?? 40 00 8B 16 E8 ?? E1 FF FF B8 ?? ?? 40 00 E8 ?? E0 FF FF 8B D0 8B 03 8B 0E E8 ?? ?? FF FF 8B C7 A3 ?? ?? 40 00 8D 55 EC 33 C0 E8 ?? D3 FF FF 8B 45 EC B9 ?? ?? 40 00 BA ?? ?? 40 00 E8 8B ED FF FF 3C 01 75 2B A1 }

  condition:
    $a
}