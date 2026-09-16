rule PEiD_01838_PseudoSigner_0_1__PE_Protect_0_9_____Anorganix_ {
  meta:
    description = "[PseudoSigner 0.1 [PE Protect 0.9] -> Anorganix]"
    ep_only     = "true"

  strings:
    $a = { 52 51 55 57 64 67 A1 30 00 85 C0 78 0D E8 07 00 00 00 58 83 C0 07 C6 90 C3 E9 }

  condition:
    $a
}