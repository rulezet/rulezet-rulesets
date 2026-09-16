rule TTP_XOR_QUAD_CurrentVersionRun_a275 {
  strings:
    $key_a275 = { f1 1a [2] d5 14 [2] fe 38 [2] d0 1a [2] c4 01 [2] cb 1b [2] d5 06 [2] d7 07 [2] cc 01 [2] d0 06 [2] cc 29 }

  condition:
    any of them
}