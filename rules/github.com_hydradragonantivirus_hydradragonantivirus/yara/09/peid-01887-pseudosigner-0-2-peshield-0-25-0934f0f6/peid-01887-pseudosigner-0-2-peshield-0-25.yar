rule PEiD_01887_PseudoSigner_0_2__PESHiELD_0_25__ {
  meta:
    description = "[PseudoSigner 0.2 [PESHiELD 0.25]]"
    ep_only     = "true"

  strings:
    $a = { 60 E8 2B 00 00 00 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 CC CC }

  condition:
    $a
}