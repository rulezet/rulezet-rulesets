rule PEiD_01844_PseudoSigner_0_1__PEX_0_99_____Anorganix_ {
  meta:
    description = "[PseudoSigner 0.1 [PEX 0.99] -> Anorganix]"
    ep_only     = "true"

  strings:
    $a = { 60 E8 01 00 00 00 55 83 C4 04 E8 01 00 00 00 90 5D 81 FF FF FF 00 01 E9 }

  condition:
    $a
}