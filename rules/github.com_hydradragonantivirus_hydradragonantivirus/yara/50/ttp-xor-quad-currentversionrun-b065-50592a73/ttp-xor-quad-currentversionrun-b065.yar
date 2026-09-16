rule TTP_XOR_QUAD_CurrentVersionRun_b065 {
  strings:
    $key_b065 = { e3 0a [2] c7 04 [2] ec 28 [2] c2 0a [2] d6 11 [2] d9 0b [2] c7 16 [2] c5 17 [2] de 11 [2] c2 16 [2] de 39 }

  condition:
    any of them
}