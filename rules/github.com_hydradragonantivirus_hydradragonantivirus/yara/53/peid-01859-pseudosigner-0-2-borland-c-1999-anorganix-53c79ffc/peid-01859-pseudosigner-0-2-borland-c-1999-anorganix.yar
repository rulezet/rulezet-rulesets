rule PEiD_01859_PseudoSigner_0_2__Borland_C___1999_____Anorganix_ {
  meta:
    description = "[PseudoSigner 0.2 [Borland C++ 1999] -> Anorganix]"
    ep_only     = "true"

  strings:
    $a = { EB 10 66 62 3A 43 2B 2B 48 4F 4F 4B 90 E9 90 90 90 90 A1 ?? ?? ?? ?? A3 }

  condition:
    $a
}