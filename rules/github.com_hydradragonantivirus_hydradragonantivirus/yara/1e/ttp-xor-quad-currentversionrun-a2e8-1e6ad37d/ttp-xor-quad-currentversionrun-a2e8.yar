rule TTP_XOR_QUAD_CurrentVersionRun_a2e8 {
  strings:
    $key_a2e8 = { f1 87 [2] d5 89 [2] fe a5 [2] d0 87 [2] c4 9c [2] cb 86 [2] d5 9b [2] d7 9a [2] cc 9c [2] d0 9b [2] cc b4 }

  condition:
    any of them
}