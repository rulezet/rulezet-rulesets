rule PEiD_01800_PseudoSigner_0_1__Borland_Delphi_3_0__ {
  meta:
    description = "[PseudoSigner 0.1 [Borland Delphi 3.0]]"
    ep_only     = "true"

  strings:
    $a = { 55 8B EC 83 C4 90 90 90 90 68 ?? ?? ?? ?? 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 }

  condition:
    $a
}