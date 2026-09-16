rule TTP_XOR_QUAD_CurrentVersionRun_a225 {
  strings:
    $key_a225 = { f1 4a [2] d5 44 [2] fe 68 [2] d0 4a [2] c4 51 [2] cb 4b [2] d5 56 [2] d7 57 [2] cc 51 [2] d0 56 [2] cc 79 }

  condition:
    any of them
}