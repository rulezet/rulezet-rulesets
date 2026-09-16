rule TTP_XOR_QUAD_CurrentVersionRun_a243 {
  strings:
    $key_a243 = { f1 2c [2] d5 22 [2] fe 0e [2] d0 2c [2] c4 37 [2] cb 2d [2] d5 30 [2] d7 31 [2] cc 37 [2] d0 30 [2] cc 1f }

  condition:
    any of them
}