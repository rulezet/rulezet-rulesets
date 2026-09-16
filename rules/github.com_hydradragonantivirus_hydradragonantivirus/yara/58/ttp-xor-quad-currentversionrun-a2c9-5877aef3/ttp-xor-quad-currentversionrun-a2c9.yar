rule TTP_XOR_QUAD_CurrentVersionRun_a2c9 {
  strings:
    $key_a2c9 = { f1 a6 [2] d5 a8 [2] fe 84 [2] d0 a6 [2] c4 bd [2] cb a7 [2] d5 ba [2] d7 bb [2] cc bd [2] d0 ba [2] cc 95 }

  condition:
    any of them
}