rule TTP_XOR_QUAD_CurrentVersionRun_a7b5 {
  strings:
    $key_a7b5 = { f4 da [2] d0 d4 [2] fb f8 [2] d5 da [2] c1 c1 [2] ce db [2] d0 c6 [2] d2 c7 [2] c9 c1 [2] d5 c6 [2] c9 e9 }

  condition:
    any of them
}