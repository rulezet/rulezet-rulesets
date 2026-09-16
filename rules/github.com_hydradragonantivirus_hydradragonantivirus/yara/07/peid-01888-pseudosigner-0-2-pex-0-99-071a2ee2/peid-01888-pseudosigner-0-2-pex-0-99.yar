rule PEiD_01888_PseudoSigner_0_2__PEX_0_99__ {
  meta:
    description = "[PseudoSigner 0.2 [PEX 0.99]]"
    ep_only     = "true"

  strings:
    $a = { 60 E8 01 00 00 00 55 83 C4 04 E8 01 00 00 00 90 5D 81 FF FF FF 00 01 }

  condition:
    $a
}