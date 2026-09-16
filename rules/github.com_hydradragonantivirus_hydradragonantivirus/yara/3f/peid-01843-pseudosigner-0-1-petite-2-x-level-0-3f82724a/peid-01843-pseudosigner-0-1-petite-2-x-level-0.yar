rule PEiD_01843_PseudoSigner_0_1__PEtite_2_x__level_0___ {
  meta:
    description = "[PseudoSigner 0.1 [PEtite 2.x (level 0)]]"
    ep_only     = "true"

  strings:
    $a = { 90 90 90 90 68 ?? ?? ?? ?? 67 64 FF 36 00 00 67 64 89 26 00 00 F1 90 90 90 90 B8 00 90 90 00 6A 00 68 90 90 90 00 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 66 9C 60 50 8B D8 03 00 68 }

  condition:
    $a
}