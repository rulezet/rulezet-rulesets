rule TTP_XOR_QUAD_CurrentVersionRun_a242 {
  strings:
    $key_a242 = { f1 2d [2] d5 23 [2] fe 0f [2] d0 2d [2] c4 36 [2] cb 2c [2] d5 31 [2] d7 30 [2] cc 36 [2] d0 31 [2] cc 1e }

  condition:
    any of them
}