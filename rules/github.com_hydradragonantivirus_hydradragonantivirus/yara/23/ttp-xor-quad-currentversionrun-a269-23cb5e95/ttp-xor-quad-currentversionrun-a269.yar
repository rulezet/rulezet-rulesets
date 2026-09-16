rule TTP_XOR_QUAD_CurrentVersionRun_a269 {
  strings:
    $key_a269 = { f1 06 [2] d5 08 [2] fe 24 [2] d0 06 [2] c4 1d [2] cb 07 [2] d5 1a [2] d7 1b [2] cc 1d [2] d0 1a [2] cc 35 }

  condition:
    any of them
}