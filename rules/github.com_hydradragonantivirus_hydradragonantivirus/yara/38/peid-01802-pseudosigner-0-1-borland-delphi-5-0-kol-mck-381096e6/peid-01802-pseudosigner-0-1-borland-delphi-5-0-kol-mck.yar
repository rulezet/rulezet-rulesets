rule PEiD_01802_PseudoSigner_0_1__Borland_Delphi_5_0_KOL_MCK__ {
  meta:
    description = "[PseudoSigner 0.1 [Borland Delphi 5.0 KOL/MCK]]"
    ep_only     = "true"

  strings:
    $a = { 55 8B EC 90 90 90 90 68 ?? ?? ?? ?? 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 00 FF 90 90 90 90 90 90 90 90 00 01 90 90 90 90 90 90 90 90 90 EB 04 00 00 00 01 90 90 90 90 90 90 90 00 01 90 90 90 90 90 90 90 90 90 }

  condition:
    $a
}