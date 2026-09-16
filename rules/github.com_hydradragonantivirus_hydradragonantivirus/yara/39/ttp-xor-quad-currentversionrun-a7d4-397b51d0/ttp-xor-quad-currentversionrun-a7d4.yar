rule TTP_XOR_QUAD_CurrentVersionRun_a7d4 {
  strings:
    $key_a7d4 = { f4 bb [2] d0 b5 [2] fb 99 [2] d5 bb [2] c1 a0 [2] ce ba [2] d0 a7 [2] d2 a6 [2] c9 a0 [2] d5 a7 [2] c9 88 }

  condition:
    any of them
}