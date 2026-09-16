rule PEiD_01805_PseudoSigner_0_1__Code_Lock_____Anorganix_ {
  meta:
    description = "[PseudoSigner 0.1 [Code-Lock] -> Anorganix]"
    ep_only     = "true"

  strings:
    $a = { 43 4F 44 45 2D 4C 4F 43 4B 2E 4F 43 58 00 01 28 01 50 4B 47 05 4C 3F B4 04 4D 4C 47 4B E9 }

  condition:
    $a
}