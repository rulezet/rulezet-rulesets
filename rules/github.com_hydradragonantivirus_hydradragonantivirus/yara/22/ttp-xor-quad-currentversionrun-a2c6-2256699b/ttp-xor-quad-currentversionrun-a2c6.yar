rule TTP_XOR_QUAD_CurrentVersionRun_a2c6 {
  strings:
    $key_a2c6 = { f1 a9 [2] d5 a7 [2] fe 8b [2] d0 a9 [2] c4 b2 [2] cb a8 [2] d5 b5 [2] d7 b4 [2] cc b2 [2] d0 b5 [2] cc 9a }

  condition:
    any of them
}