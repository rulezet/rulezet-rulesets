rule TTP_XOR_QUAD_CurrentVersionRun_a2d7 {
  strings:
    $key_a2d7 = { f1 b8 [2] d5 b6 [2] fe 9a [2] d0 b8 [2] c4 a3 [2] cb b9 [2] d5 a4 [2] d7 a5 [2] cc a3 [2] d0 a4 [2] cc 8b }

  condition:
    any of them
}