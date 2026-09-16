rule TTP_XOR_QUAD_CurrentVersionRun_a259 {
  strings:
    $key_a259 = { f1 36 [2] d5 38 [2] fe 14 [2] d0 36 [2] c4 2d [2] cb 37 [2] d5 2a [2] d7 2b [2] cc 2d [2] d0 2a [2] cc 05 }

  condition:
    any of them
}