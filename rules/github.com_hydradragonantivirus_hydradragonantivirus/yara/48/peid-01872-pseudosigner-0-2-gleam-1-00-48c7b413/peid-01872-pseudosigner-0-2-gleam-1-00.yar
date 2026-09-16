rule PEiD_01872_PseudoSigner_0_2__Gleam_1_00__ {
  meta:
    description = "[PseudoSigner 0.2 [Gleam 1.00]]"
    ep_only     = "true"

  strings:
    $a = { 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 EB 0B 83 EC 0C 53 56 57 E8 24 02 00 FF }

  condition:
    $a
}