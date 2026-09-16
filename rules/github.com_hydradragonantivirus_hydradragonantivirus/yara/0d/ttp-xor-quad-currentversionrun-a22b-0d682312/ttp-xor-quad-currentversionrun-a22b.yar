rule TTP_XOR_QUAD_CurrentVersionRun_a22b {
  strings:
    $key_a22b = { f1 44 [2] d5 4a [2] fe 66 [2] d0 44 [2] c4 5f [2] cb 45 [2] d5 58 [2] d7 59 [2] cc 5f [2] d0 58 [2] cc 77 }

  condition:
    any of them
}