rule PEiD_01854_PseudoSigner_0_2___BJFNT_1_1b__ {
  meta:
    description = "[PseudoSigner 0.2 [.BJFNT 1.1b]]"
    ep_only     = "true"

  strings:
    $a = { EB 01 EA 9C EB 01 EA 53 EB 01 EA 51 EB 01 EA 52 EB 01 EA 56 90 }

  condition:
    $a
}