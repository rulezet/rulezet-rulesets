rule TTP_XOR_QUAD_CurrentVersionRun_a239 {
  strings:
    $key_a239 = { f1 56 [2] d5 58 [2] fe 74 [2] d0 56 [2] c4 4d [2] cb 57 [2] d5 4a [2] d7 4b [2] cc 4d [2] d0 4a [2] cc 65 }

  condition:
    any of them
}