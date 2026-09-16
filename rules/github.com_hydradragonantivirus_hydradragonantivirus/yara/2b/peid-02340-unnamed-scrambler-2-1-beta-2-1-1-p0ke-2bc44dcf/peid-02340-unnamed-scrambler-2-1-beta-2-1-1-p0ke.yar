rule PEiD_02340_Unnamed_Scrambler_2_1_Beta____2_1_1____p0ke_ {
  meta:
    description = "[Unnamed Scrambler 2.1(Beta) / 2.1.1 -> p0ke]"
    ep_only     = "true"

  strings:
    $a = { 55 8B EC B9 15 00 00 00 6A 00 6A 00 49 75 F9 53 56 57 B8 ?? 3A ?? ?? E8 ?? EE FF FF 33 C0 55 68 ?? 43 ?? ?? 64 FF 30 64 89 20 BA ?? 43 ?? ?? B8 E4 64 ?? ?? E8 0F FD FF FF 8B D8 85 DB 75 07 6A 00 E8 ?? EE FF FF BA E8 64 ?? ?? 8B C3 8B 0D E4 64 ?? ?? E8 }

  condition:
    $a
}