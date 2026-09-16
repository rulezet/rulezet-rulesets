rule PEiD_01862_PseudoSigner_0_2__Borland_Delphi_Setup_Module__ {
  meta:
    description = "[PseudoSigner 0.2 [Borland Delphi Setup Module]]"
    ep_only     = "true"

  strings:
    $a = { 55 8B EC 83 C4 90 53 56 57 33 C0 89 45 F0 89 45 D4 89 45 D0 E8 00 00 00 00 }

  condition:
    $a
}