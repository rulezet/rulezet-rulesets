rule TTP_XOR_QUAD_CurrentVersionRun_a5d4 {
  strings:
    $key_a5d4 = { f6 bb [2] d2 b5 [2] f9 99 [2] d7 bb [2] c3 a0 [2] cc ba [2] d2 a7 [2] d0 a6 [2] cb a0 [2] d7 a7 [2] cb 88 }

  condition:
    any of them
}