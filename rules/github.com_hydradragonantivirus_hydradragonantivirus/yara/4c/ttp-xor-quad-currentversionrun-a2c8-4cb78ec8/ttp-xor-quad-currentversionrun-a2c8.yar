rule TTP_XOR_QUAD_CurrentVersionRun_a2c8 {
  strings:
    $key_a2c8 = { f1 a7 [2] d5 a9 [2] fe 85 [2] d0 a7 [2] c4 bc [2] cb a6 [2] d5 bb [2] d7 ba [2] cc bc [2] d0 bb [2] cc 94 }

  condition:
    any of them
}