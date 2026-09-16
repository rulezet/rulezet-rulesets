rule TTP_XOR_QUAD_CurrentVersionRun_a247 {
  strings:
    $key_a247 = { f1 28 [2] d5 26 [2] fe 0a [2] d0 28 [2] c4 33 [2] cb 29 [2] d5 34 [2] d7 35 [2] cc 33 [2] d0 34 [2] cc 1b }

  condition:
    any of them
}