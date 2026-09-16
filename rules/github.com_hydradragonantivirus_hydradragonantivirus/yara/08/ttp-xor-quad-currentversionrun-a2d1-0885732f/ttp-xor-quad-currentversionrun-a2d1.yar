rule TTP_XOR_QUAD_CurrentVersionRun_a2d1 {
  strings:
    $key_a2d1 = { f1 be [2] d5 b0 [2] fe 9c [2] d0 be [2] c4 a5 [2] cb bf [2] d5 a2 [2] d7 a3 [2] cc a5 [2] d0 a2 [2] cc 8d }

  condition:
    any of them
}