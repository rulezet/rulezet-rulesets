rule TTP_XOR_QUAD_CurrentVersionRun_a2d4 {
  strings:
    $key_a2d4 = { f1 bb [2] d5 b5 [2] fe 99 [2] d0 bb [2] c4 a0 [2] cb ba [2] d5 a7 [2] d7 a6 [2] cc a0 [2] d0 a7 [2] cc 88 }

  condition:
    any of them
}