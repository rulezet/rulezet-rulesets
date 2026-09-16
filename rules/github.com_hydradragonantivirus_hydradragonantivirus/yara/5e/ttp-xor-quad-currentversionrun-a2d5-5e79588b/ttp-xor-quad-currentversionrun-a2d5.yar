rule TTP_XOR_QUAD_CurrentVersionRun_a2d5 {
  strings:
    $key_a2d5 = { f1 ba [2] d5 b4 [2] fe 98 [2] d0 ba [2] c4 a1 [2] cb bb [2] d5 a6 [2] d7 a7 [2] cc a1 [2] d0 a6 [2] cc 89 }

  condition:
    any of them
}