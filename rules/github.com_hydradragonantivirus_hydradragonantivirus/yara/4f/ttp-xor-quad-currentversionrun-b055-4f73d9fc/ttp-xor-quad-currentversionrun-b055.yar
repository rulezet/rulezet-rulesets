rule TTP_XOR_QUAD_CurrentVersionRun_b055 {
  strings:
    $key_b055 = { e3 3a [2] c7 34 [2] ec 18 [2] c2 3a [2] d6 21 [2] d9 3b [2] c7 26 [2] c5 27 [2] de 21 [2] c2 26 [2] de 09 }

  condition:
    any of them
}