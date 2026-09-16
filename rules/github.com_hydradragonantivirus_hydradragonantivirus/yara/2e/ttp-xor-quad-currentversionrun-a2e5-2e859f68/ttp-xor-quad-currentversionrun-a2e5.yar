rule TTP_XOR_QUAD_CurrentVersionRun_a2e5 {
  strings:
    $key_a2e5 = { f1 8a [2] d5 84 [2] fe a8 [2] d0 8a [2] c4 91 [2] cb 8b [2] d5 96 [2] d7 97 [2] cc 91 [2] d0 96 [2] cc b9 }

  condition:
    any of them
}