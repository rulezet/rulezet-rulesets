rule TTP_XOR_QUAD_CurrentVersionRun_a2e9 {
  strings:
    $key_a2e9 = { f1 86 [2] d5 88 [2] fe a4 [2] d0 86 [2] c4 9d [2] cb 87 [2] d5 9a [2] d7 9b [2] cc 9d [2] d0 9a [2] cc b5 }

  condition:
    any of them
}