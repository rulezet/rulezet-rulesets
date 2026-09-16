rule TTP_XOR_QUAD_CurrentVersionRun_b077 {
  strings:
    $key_b077 = { e3 18 [2] c7 16 [2] ec 3a [2] c2 18 [2] d6 03 [2] d9 19 [2] c7 04 [2] c5 05 [2] de 03 [2] c2 04 [2] de 2b }

  condition:
    any of them
}