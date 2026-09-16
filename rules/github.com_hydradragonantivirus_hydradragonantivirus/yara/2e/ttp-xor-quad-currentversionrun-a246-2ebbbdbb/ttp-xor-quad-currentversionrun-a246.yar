rule TTP_XOR_QUAD_CurrentVersionRun_a246 {
  strings:
    $key_a246 = { f1 29 [2] d5 27 [2] fe 0b [2] d0 29 [2] c4 32 [2] cb 28 [2] d5 35 [2] d7 34 [2] cc 32 [2] d0 35 [2] cc 1a }

  condition:
    any of them
}