rule TTP_XOR_QUAD_CurrentVersionRun_a055 {
  strings:
    $key_a055 = { f3 3a [2] d7 34 [2] fc 18 [2] d2 3a [2] c6 21 [2] c9 3b [2] d7 26 [2] d5 27 [2] ce 21 [2] d2 26 [2] ce 09 }

  condition:
    any of them
}