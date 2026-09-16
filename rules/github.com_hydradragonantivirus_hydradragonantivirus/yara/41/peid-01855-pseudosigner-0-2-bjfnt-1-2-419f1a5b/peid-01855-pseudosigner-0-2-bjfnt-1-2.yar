rule PEiD_01855_PseudoSigner_0_2___BJFNT_1_2__ {
  meta:
    description = "[PseudoSigner 0.2 [.BJFNT 1.2]]"
    ep_only     = "true"

  strings:
    $a = { EB 02 69 B1 83 EC 04 EB 03 CD 20 EB EB 01 EB 9C EB 01 EB EB 00 }

  condition:
    $a
}